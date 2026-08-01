#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui.py - Interfaz web local de AlienProbe.
Capa delgada sobre el nucleo dynadb.py + core/access.py. Sirve una SPA (index.html)
con tema oscuro/neon y expone la API JSON que la consume.

Arranque:  python run.py   (run.py detecta gui.py y lo lanza)
Manual:    python gui.py [--host 127.0.0.1] [--port 8765] [--no-browser]

No duplica logica del core: importa funciones de dynadb y core.access.
El CLI dynadb.py sigue siendo totalmente operativo.
"""
import argparse, os, sys, json, threading, webbrowser, base64, datetime, shutil, re, time, subprocess

# Asegurar que el directorio base esta en sys.path para importar dynadb y core
BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

import dynadb
from core import access
from core import instrument
from core import report_log

PRESETS_FILE = os.path.join(BASE, "presets.json")
HELP_FILE = os.path.join(BASE, "ui_help.json")


def load_presets():
    """Carga el catalogo data-driven de presets. Devuelve lista de dicts."""
    try:
        data = json.load(open(PRESETS_FILE, encoding="utf-8"))
        return data.get("presets", []) if isinstance(data, dict) else (data or [])
    except Exception as e:
        print("[!] No pude leer presets.json: %s" % e)
        return []


def find_preset(pid):
    for p in load_presets():
        if p.get("id") == pid:
            return p
    return None

try:
    from flask import Flask, request, jsonify, send_from_directory, Response
except Exception as e:
    print("[X] Falta Flask. Instala requirements.txt (python run.py lo hace).")
    print("    pip install flask")
    raise

app = Flask(__name__, static_folder=BASE)

# ---------------- estado de sesion en memoria ----------------
STATE = {
    "adb": None,        # ruta resuelta
    "serial": None,     # dispositivo seleccionado
    "package": None,    # app target
    "mode": "auto",      # auto | root | runas
    "access_mode": None, # detectado para el target
}


# ---------------- helpers ----------------
def _set_adb():
    """Fija dynadb.ADB desde config o PATH SIN prompt (la GUI gestiona la ruta por su panel)."""
    cfg = dynadb.load_config()
    p = cfg.get("adb")
    if p and os.path.exists(p):
        dynadb.ADB = p
    else:
        dynadb.ADB = shutil.which("adb") or "adb"


def _ok(data=None):
    return jsonify({"ok": True, "data": data})


def _err(msg, code=400):
    return jsonify({"ok": False, "error": str(msg)}), code

@app.errorhandler(Exception)
def _json_error(e):
    # Cualquier excepcion se devuelve como JSON (evita el "respuesta no JSON" en la GUI)
    import traceback
    return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()[-800:]}), 500


# ---------------- API: config adb ----------------
@app.get("/api/adb/status")
def adb_status():
    _set_adb()
    cfg = dynadb.load_config()
    return _ok({"adb": dynadb.ADB, "in_path": bool(dynadb.ADB) and os.path.basename(dynadb.ADB) == "adb" or (cfg.get("adb") is not None)})

@app.post("/api/adb/set")
def adb_set():
    path = (request.json or {}).get("path", "").strip().strip('"')
    if not path or not os.path.exists(path):
        return _err("Ruta invalida: %s" % path)
    cfg = dynadb.load_config()
    cfg["adb"] = path
    dynadb.save_config(cfg)
    dynadb.ADB = path
    return _ok({"adb": path})

@app.post("/api/adb/test")
def adb_test():
    _set_adb()
    rc, out, err = dynadb.adb(["version"])
    if rc == 0 and out:
        return _ok({"version": out.splitlines()[0].strip()})
    return _err((err or out or "adb no responde").strip())


# ---------------- API: dispositivos ----------------
@app.get("/api/devices")
def devices():
    _set_adb()
    serial = STATE.get("serial")
    rows = dynadb.devices_list(serial)
    # enriquecemos con perfil ligero (root/api/arch) solo para los 'device'
    for r in rows:
        if r["state"] == "device":
            try:
                prof = dynadb.device_profile(r["serial"])
                r.update({"api": prof["api"], "arch": prof["arch"], "model": prof["model"], "root": prof["root"]})
            except Exception as e:
                r.update({"api": "?", "arch": "?", "model": "?", "root": False, "error": str(e)})
        else:
            r.update({"api": "?", "arch": "?", "model": "?", "root": False})
    return _ok(rows)

@app.post("/api/devices/connect")
def devices_connect():
    _set_adb()
    hostport = (request.json or {}).get("hostport", "").strip()
    if not hostport:
        return _err("Falta host:port (ej. 127.0.0.1:62001)")
    msg = dynadb.connect_host(hostport)
    return _ok({"message": msg})

@app.post("/api/devices/autoconnect")
def devices_autoconnect():
    _set_adb()
    res = dynadb.autoconnect()
    return _ok({"connected": res})

@app.post("/api/devices/select")
def devices_select():
    serial = (request.json or {}).get("serial", "").strip()
    STATE["serial"] = serial or None
    cfg = dynadb.load_config()
    if serial:
        cfg["serial"] = serial
        dynadb.save_config(cfg)
        # §9 recomendacion UX: auto-arrancar frida-server en segundo plano al
        # elegir device, para que el chip sea honesto sin que el usuario toque
        # nada manual tras reiniciar el emulador.
        _bg_ensure_frida(serial)
    return _ok({"serial": STATE["serial"]})


# ---------------- API: apps ----------------
@app.get("/api/packages")
def packages():
    _set_adb()
    serial = STATE.get("serial")
    filt = (request.args.get("filter") or "").strip().lower()
    allp = request.args.get("all") == "1"
    pkgs = dynadb.list_packages(serial, third_party=not allp)
    if filt:
        pkgs = [p for p in pkgs if filt in p.lower()]
    return _ok(pkgs)

@app.post("/api/packages/install")
def packages_install():
    _set_adb()
    path = (request.json or {}).get("path", "").strip().strip('"')
    if not path or not os.path.exists(path):
        return _err("APK no encontrada: %s" % path)
    rc, msg = dynadb.install_apk(path, STATE.get("serial"), replace=True)
    return jsonify({"ok": rc == 0, "rc": rc, "message": msg})

@app.post("/api/target/select")
def target_select():
    pkg = (request.json or {}).get("package", "").strip()
    STATE["package"] = pkg or None
    if not pkg:
        return _ok({"package": None, "access_mode": None})
    _set_adb()
    try:
        m = access.get_access_mode(pkg, STATE.get("serial"), prefer=STATE.get("mode", "auto"))
    except Exception as e:
        return _err("No pude determinar el modo de acceso: %s" % e)
    STATE["access_mode"] = m
    report_log.set_meta(pkg=pkg, device=STATE.get("serial"))
    return _ok({"package": pkg, "access_mode": m})


# ---------------- API: analisis ----------------
@app.get("/api/info")
def info():
    _set_adb()
    pkg = STATE.get("package") or (request.args.get("package") or "").strip()
    if not pkg:
        return _err("Selecciona una app primero")
    d = dynadb.info_data(pkg, STATE.get("serial"))
    if not d:
        return _err("Paquete %s no encontrado (¿instalado?)" % pkg)
    d["access_mode"] = access.get_access_mode(pkg, STATE.get("serial"), prefer=STATE.get("mode", "auto"))
    return _ok(d)

@app.get("/api/components")
def components():
    _set_adb()
    pkg = STATE.get("package") or (request.args.get("package") or "").strip()
    if not pkg:
        return _err("Selecciona una app primero")
    comps, exported = dynadb.components_data(pkg, STATE.get("serial"))
    if exported:
        report_log.log_action("components", pkg,
            evidencia="Exportados:\n" + "\n".join(sorted(exported)[:40]))
    return _ok({"components": sorted(comps), "exported": sorted(exported)})

@app.get("/api/storage")
def storage():
    _set_adb()
    pkg = STATE.get("package")
    if not pkg:
        return _err("Selecciona una app primero")
    res = dynadb.storage_data(pkg, STATE.get("serial"), outdir=os.path.join(BASE, "loot"), mode=STATE.get("mode", "auto"))
    finds = res.get("findings") or res.get("secrets") or []
    if finds:
        ev = []
        for f in finds[:30]:
            if isinstance(f, dict):
                ev.append("- %s: %s" % (f.get("source") or f.get("key") or "?", f.get("value") or f.get("match") or f))
            else:
                ev.append("- %s" % str(f))
        report_log.log_action("storage", pkg, evidencia="\n".join(ev))
    return _ok(res)

@app.post("/api/launch")
def launch():
    _set_adb()
    pkg = STATE.get("package")
    if not pkg:
        return _err("Selecciona una app primero")
    body = request.json or {}
    activity = body.get("activity", "").strip()
    if not activity:
        return _err("Indica un activity (ej. .ui.AccountActivity)")
    ei = body.get("ei", [])   # [[k,v],...]
    es = body.get("es", [])
    args = ["shell", "am", "start", "-n", "%s/%s" % (pkg, activity)]
    for kv in ei or []:
        if len(kv) == 2:
            args += ["--ei", str(kv[0]), str(kv[1])]
    for kv in es or []:
        if len(kv) == 2:
            args += ["--es", str(kv[0]), str(kv[1])]
    rc, out, err = dynadb.adb(args, STATE.get("serial"))
    blob = (out + err).strip()
    verdict = "ok" if (rc == 0 and "Starting" in blob) else ("denied" if "Permission Denial" in blob else "unknown")
    if verdict == "ok":
        # Si se pasó un id (IDOR) lo tratamos como acceso a objeto; si no, activity exportada.
        key = "launch_idor" if (ei or es) else "exported_admin"
        report_log.log_action(key, pkg,
            evidencia="am start -n %s/%s  %s\n%s" % (pkg, activity,
                      " ".join("--ei %s %s" % (k, v) for k, v in (ei or [])), blob[:400]))
    return _ok({"rc": rc, "output": blob, "verdict": verdict})

@app.get("/api/screenshot")
def screenshot():
    _set_adb()
    rc, data, err = dynadb.adb(["exec-out", "screencap", "-p"], STATE.get("serial"), binary=True)
    if rc == 0 and data[:8] == b"\x89PNG\r\n\x1a\n":
        b64 = base64.b64encode(data).decode("ascii")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(BASE, "loot", "screenshot_%s.png" % ts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb").write(data)
        report_log.log_action("screenshot", STATE.get("package"),
            evidencia="Captura guardada: %s" % path, extra={"img_path": path})
        return _ok({"png_base64": b64, "saved": path})
    return _err((err or "formato inesperado").strip())

@app.get("/api/loot/<path:name>")
def loot_file(name):
    """Sirve archivos de loot/ (capturas, etc.) por una URL normal, para poder abrirlos
    a tamaño completo o descargarlos (los navegadores bloquean abrir data: como página)."""
    safe = os.path.basename(name)
    d = os.path.join(BASE, "loot")
    if not os.path.exists(os.path.join(d, safe)):
        return _err("no existe", 404)
    return send_from_directory(d, safe)


@app.get("/api/logcat")
def logcat():
    _set_adb()
    pkg = STATE.get("package") or (request.args.get("package") or "").strip()
    if not pkg:
        return _err("Selecciona una app primero")
    lines = int(request.args.get("lines", 200))
    rc, pid, _ = dynadb.adb(["shell", "pidof", "-s", pkg], STATE.get("serial"))
    pid = (pid or "").strip()
    if pid:
        rc, out, _ = dynadb.adb(["logcat", "-d", "--pid", pid, "-t", str(lines)], STATE.get("serial"))
    else:
        rc, out, _ = dynadb.adb(["logcat", "-d", "-t", str(lines * 5)], STATE.get("serial"))
        key = pkg.split(".")[-1]
        out = "\n".join(l for l in out.splitlines() if key.lower() in l.lower())
    return _ok({"lines": out.strip(), "pid": pid})

@app.post("/api/report")
def report():
    _set_adb()
    pkg = STATE.get("package")
    if not pkg:
        return _err("Selecciona una app primero")
    # Reusamos cmd_report del core via Namespace
    import argparse
    ns = argparse.Namespace(package=pkg, serial=STATE.get("serial"), out=os.path.join(BASE, "loot"))
    dynadb.cmd_report(ns)
    outdir = os.path.join(BASE, "loot", pkg)
    md = os.path.join(outdir, "informe.md")
    content = open(md, encoding="utf-8").read() if os.path.exists(md) else ""
    return _ok({"path": md, "content": content, "dir": outdir})

@app.get("/api/frida/scripts")
def frida_scripts_list():
    d = os.path.join(BASE, "frida_scripts")
    items = []
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".js"):
                desc = ""
                try:
                    desc = open(os.path.join(d, fn), encoding="utf-8").readline().strip().lstrip("/ ").strip()
                except Exception:
                    pass
                items.append({"name": fn, "desc": desc, "path": os.path.join(d, fn)})
    return _ok(items)

@app.get("/api/state")
def state():
    return _ok({
        "adb": dynadb.ADB,
        "serial": STATE.get("serial"),
        "package": STATE.get("package"),
        "mode": STATE.get("mode"),
        "access_mode": STATE.get("access_mode"),
    })

@app.post("/api/mode")
def set_mode():
    STATE["mode"] = (request.json or {}).get("mode", "auto")
    if STATE.get("package"):
        STATE["access_mode"] = access.get_access_mode(STATE["package"], STATE.get("serial"), prefer=STATE["mode"])
    return _ok({"mode": STATE["mode"], "access_mode": STATE.get("access_mode")})

@app.get("/api/report/download")
def report_download():
    pkg = STATE.get("package") or (request.args.get("package") or "").strip()
    if not pkg:
        return _err("Selecciona una app")
    md = os.path.join(BASE, "loot", pkg, "informe.md")
    if not os.path.exists(md):
        return _err("Genera el informe primero")
    return Response(open(md, encoding="utf-8").read(), mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=informe_%s.md" % pkg})


# ---------- Informe ACUMULATIVO (ledger de hallazgos en vivo) ----------
@app.get("/api/report/log")
def report_log_list():
    return _ok({"entries": report_log.items(), "meta": report_log.get_meta()})

@app.post("/api/report/log/note")
def report_log_note():
    txt = ((request.json or {}).get("text") or "").strip()
    if not txt:
        return _err("Escribe una nota")
    report_log.add_note(txt)
    return _ok({"entries": len(report_log.items())})

@app.post("/api/report/log/clear")
def report_log_clear():
    report_log.clear()
    return _ok({"cleared": True})

@app.get("/api/report/log/download")
def report_log_download():
    pkg = STATE.get("package") or report_log.get_meta().get("pkg") or "app"
    dev = STATE.get("serial")
    fmt = (request.args.get("format") or "md").lower()
    outdir = os.path.join(BASE, "loot", pkg)
    try:
        os.makedirs(outdir, exist_ok=True)
    except Exception:
        pass
    if fmt == "html":
        htmlrep = report_log.render_html(pkg=pkg, device=dev)
        try:
            open(os.path.join(outdir, "informe_dinamico.html"), "w", encoding="utf-8").write(htmlrep)
        except Exception:
            pass
        return Response(htmlrep, mimetype="text/html",
                        headers={"Content-Disposition": "attachment; filename=informe_dinamico_%s.html" % pkg})
    md = report_log.render_md(pkg=pkg, device=dev)
    try:
        open(os.path.join(outdir, "informe_dinamico.md"), "w", encoding="utf-8").write(md)
    except Exception:
        pass
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=informe_dinamico_%s.md" % pkg})


@app.post("/api/audit")
def audit_run():
    pkg = STATE.get("package")
    if not pkg:
        return _err("Selecciona una app primero")
    return _run_audit(pkg, STATE.get("serial"))


# ---------------- API: presets ----------------
@app.get("/api/presets")
def presets_list():
    return _ok(load_presets())


# ---------------- API: Cazador de secretos (modulo adicional, jadx) ----------------
@app.get("/api/hunt/status")
def hunt_status():
    try:
        from core import hunter
        return _ok(hunter.status())
    except Exception as e:
        return _err("Cazador no disponible: %s" % e)


@app.post("/api/hunt/install")
def hunt_install():
    try:
        from core import hunter
        return _ok(hunter.install_jadx())
    except Exception as e:
        return _err("No pude instalar jadx: %s" % e)


@app.post("/api/hunt/upload")
def hunt_upload():
    f = request.files.get("apk")
    if not f:
        return _err("No llegó ningún archivo.")
    os.makedirs(os.path.join(BASE, "loot"), exist_ok=True)
    dest = os.path.join(BASE, "loot", "_hunt_upload.apk")
    try:
        f.save(dest)
    except Exception as e:
        return _err("No pude guardar el APK: %s" % e)
    return _ok({"path": dest, "name": f.filename})


@app.post("/api/launch/extras")
def launch_extras():
    try:
        from core import hunter
    except Exception as e:
        return _err("Consulta de extras no disponible: %s" % e)
    _set_adb()
    body = request.json or {}
    res = hunter.activity_extras(STATE.get("package"), STATE.get("serial"), dynadb.adb,
                                 activity=(body.get("activity") or "").strip())
    return _ok(res)


@app.post("/api/hunt/asset")
def hunt_asset():
    try:
        from core import hunter
    except Exception as e:
        return _err("Cazador no disponible: %s" % e)
    _set_adb()
    body = request.json or {}
    res = hunter.decode_asset(STATE.get("package"), STATE.get("serial"), dynadb.adb,
                              apk_path=(body.get("apk_path") or None),
                              name=body.get("name", "assets/config.dat"))
    try:
        if res.get("flags") and STATE.get("package"):
            report_log.log_action("static_scan", STATE.get("package"),
                evidencia="Asset decodificado (%s): %s" % (res.get("asset"), ", ".join(res["flags"])))
    except Exception:
        pass
    return _ok(res)


@app.post("/api/hunt/context")
def hunt_context():
    try:
        from core import hunter
    except Exception as e:
        return _err("Cazador no disponible: %s" % e)
    _set_adb()
    body = request.json or {}
    res = hunter.context(STATE.get("package"), STATE.get("serial"), dynadb.adb,
                         apk_path=(body.get("apk_path") or None),
                         file=body.get("file", ""),
                         line=int(body.get("line") or 0),
                         radius=int(body.get("radius") or 3))
    return _ok(res)


@app.post("/api/hunt")
def hunt_run():
    try:
        from core import hunter
    except Exception as e:
        return _err("Cazador no disponible: %s" % e)
    _set_adb()
    body = request.json or {}
    pkg = STATE.get("package")
    serial = STATE.get("serial")
    apk_path = (body.get("apk_path") or "").strip()
    if not pkg and not apk_path:
        return _err("Selecciona una app o indica la ruta de un APK.")
    res = hunter.hunt(pkg, serial, dynadb.adb,
                      apk_path=apk_path or None,
                      preset=body.get("preset", "quick"),
                      query=body.get("query", ""),
                      use_jadx=bool(body.get("use_jadx", True)))
    # Registro opcional en el informe si aparecieron flags (no rompe si falla).
    try:
        flags = [r["value"] for r in res.get("results", []) if str(r.get("type", "")).startswith("👽")]
        if flags and pkg:
            report_log.log_action("static_scan", pkg,
                                  evidencia="Cazador estático: " + ", ".join(sorted(set(flags))[:20]))
    except Exception:
        pass
    return _ok(res)


# ---------------- API: Extractor de APKs (modulo adicional) ----------------
@app.get("/api/apkx/list")
def apkx_list():
    _set_adb()
    serial = STATE.get("serial")
    q = (request.args.get("q") or "").strip().lower()
    third = request.args.get("third", "1") != "0"
    args = ["shell", "pm", "list", "packages"]
    if third:
        args += ["-3"]
    rc, out, err = dynadb.adb(args, serial)
    if rc != 0 and not out:
        return _err((err or "adb no respondió (¿dispositivo conectado?)").strip())
    pkgs = []
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if ln.startswith("package:"):
            p = ln.split("package:", 1)[1].strip()
            if p and (not q or q in p.lower()):
                pkgs.append(p)
    pkgs.sort()
    return _ok({"packages": pkgs, "count": len(pkgs), "third": third})


@app.post("/api/apkx/pull")
def apkx_pull():
    _set_adb()
    serial = STATE.get("serial")
    body = request.json or {}
    pkg = (body.get("package") or "").strip()
    if not pkg:
        return _err("Indica el paquete a extraer.")
    rc, out, err = dynadb.adb(["shell", "pm", "path", pkg], serial)
    paths = [l.split("package:", 1)[1].strip() for l in (out or "").splitlines() if l.startswith("package:")]
    if not paths:
        return _err("No encontré el APK de %s en el dispositivo (¿está instalado?)." % pkg)
    base = next((p for p in paths if p.endswith("base.apk")), paths[0])
    os.makedirs(os.path.join(BASE, "loot"), exist_ok=True)
    dest = os.path.join(BASE, "loot", pkg + ".apk")
    prc, pout, perr = dynadb.adb(["pull", base, dest], serial, timeout=300)
    ok = os.path.exists(dest) and os.path.getsize(dest) > 0
    if not ok:
        detail = (perr or pout or "").strip() or "adb no devolvió detalle"
        return _err("No pude extraer el APK (adb pull falló).\nOrigen: %s\n%s" % (base, detail))
    size = os.path.getsize(dest)
    try:
        if ok:
            report_log.log_action("pull_apk", pkg,
                evidencia="APK extraído: %s (%d bytes) desde %s" % (dest, size, base))
    except Exception:
        pass
    return _ok({"package": pkg, "device_paths": paths, "splits": len(paths) > 1,
                "saved": dest if ok else None, "size": size,
                "download": ("/api/loot/" + pkg + ".apk") if ok else None,
                "base": base})


# ---------------- API: consola ADB + acciones por app (modulo ADB) ----------------
@app.post("/api/adb/run")
def adb_run():
    import shlex
    _set_adb()
    body = request.json or {}
    cmd = (body.get("cmd") or "").strip()
    if not cmd:
        return _err("Escribe un comando (sin el 'adb' inicial, ej: shell pm list packages -3).")
    if cmd.lower().startswith("adb "):
        cmd = cmd[4:].strip()
    try:
        parts = shlex.split(cmd)
    except Exception as e:
        return _err("Comando inválido: %s" % e)
    if not parts:
        return _err("Comando vacío.")
    rc, out, err = dynadb.adb(parts, STATE.get("serial"))
    blob = ((out or "") + (("\n" + err) if err else "")).strip()
    return _ok({"rc": rc, "output": blob[:8000], "cmd": "adb " + cmd})


@app.post("/api/adb/app")
def adb_app():
    _set_adb()
    body = request.json or {}
    pkg = (body.get("package") or "").strip()
    action = (body.get("action") or "").strip()
    serial = STATE.get("serial")
    if not pkg:
        return _err("Indica el paquete.")
    m = {
        "info":      ["shell", "dumpsys", "package", pkg],
        "forcestop": ["shell", "am", "force-stop", pkg],
        "cleardata": ["shell", "pm", "clear", pkg],
        "uninstall": ["uninstall", pkg],
        "open":      ["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
    }
    if action not in m:
        return _err("Acción no soportada.")
    rc, out, err = dynadb.adb(m[action], serial)
    blob = ((out or "") + (("\n" + err) if err else "")).strip()
    if action == "info":
        keep = []
        for ln in blob.splitlines():
            if re.search(r'(versionName|versionCode|targetSdk|minSdk|firstInstallTime|lastUpdateTime|'
                         r'dataDir|codePath|primaryCpuAbi|requested permissions|android\.permission|exported=true)',
                         ln):
                keep.append(ln.strip())
        blob = "\n".join(keep[:70]) or blob[:2000]
    return _ok({"action": action, "package": pkg, "rc": rc, "output": blob[:6000]})


# ---------------- API: help contextual (v3.2) ----------------
@app.get("/api/help")
def ui_help():
    """Devuelve el catalogo ui_help.json (tooltips + ayudas largas + guias)."""
    try:
        data = json.load(open(HELP_FILE, encoding="utf-8"))
        return _ok(data)
    except Exception as e:
        return _err("No pude leer ui_help.json: %s" % e)


# ---------------- API: Frida ----------------
@app.get("/api/frida/status")
def frida_status():
    serial = STATE.get("serial")
    has = instrument.has_frida()
    if not has:
        return _ok({"available": False, "running": False, "version": None,
                    "error": "frida no instalado en el venv. Usa setup_frida.py con el venv."})
    ok, ver, err = instrument.server_status(serial)
    return _ok({"available": True, "running": ok, "version": ver, "error": err})


@app.post("/api/frida/server/start")
def frida_server_start():
    """Sube y arranca frida-server en el device. Devuelve {running, version, error, push_output}."""
    venv_py = os.path.join(BASE, ".venv", "Scripts", "python.exe") if os.name == "nt" \
        else os.path.join(BASE, ".venv", "bin", "python")
    if not os.path.exists(venv_py):
        return _err("venv no encontrado. Ejecuta 'python run.py' primero.")
    # 1) Verificar que frida esta instalado en el venv
    try:
        rv = subprocess.run([venv_py, "-c", "import frida; print(frida.__version__)"],
                            capture_output=True, text=True, timeout=10)
        if rv.returncode != 0:
            return _err("frida-tools no esta en el venv. Ejecuta: %s -m pip install frida-tools" % venv_py)
        frida_ver = (rv.stdout or "").strip()
    except Exception as e:
        return _err("No pude verificar frida en el venv: %s" % e)

    _set_adb()
    serial = STATE.get("serial")
    # 2) Detectar arquitectura del device
    rc, abi, err = dynadb.adb(["shell", "getprop", "ro.product.cpu.abi"], serial)
    abi = (abi or "").strip()
    if not abi:
        return _err("No pude leer la arquitectura del device. ¿Esta conectado? (adb: %s)" % err)
    arch_map = {"x86_64":"x86_64","x86":"x86","arm64-v8a":"arm64","armeabi-v7a":"arm"}
    arch = arch_map.get(abi)
    if not arch:
        return _err("Arquitectura no soportada por frida: %s" % abi)

    # 3) Descargar/subir frida-server si no existe ya en el device
    name = "frida-server-%s-android-%s" % (frida_ver, arch)
    url  = "https://github.com/frida/frida/releases/download/%s/%s.xz" % (frida_ver, name)
    xz   = os.path.join(BASE, name + ".xz")
    out  = os.path.join(BASE, "frida-server")
    push_log = ""
    need_push = True
    # Comprobar si ya existe en el device Y su version COINCIDE con la de frida del venv.
    # (Antes solo miraba si existia -> tras cambiar la version de frida quedaba un server
    #  viejo y frida daba 'version mismatch'/'jailed'. Ahora re-sube si no coincide.)
    rc, chk, _ = dynadb.adb(["shell", "ls", "-l", "/data/local/tmp/frida-server"], serial)
    if rc == 0 and chk.strip() and os.path.exists(out):
        rc2, dev_ver, _ = dynadb.adb(
            ["shell", "su", "-c", "/data/local/tmp/frida-server --version 2>/dev/null"], serial)
        dev_ver = (dev_ver or "").strip().split()[0] if dev_ver else ""
        if dev_ver == frida_ver:
            need_push = False
            push_log = "[i] frida-server %s ya en el device (coincide con el venv)" % frida_ver
        else:
            push_log = "[i] frida-server del device (%s) != venv (%s) -> re-subiendo la version correcta\n" \
                       % (dev_ver or "desconocida", frida_ver)
    if need_push:
        # Descargar si no tenemos el xz
        if not os.path.exists(xz):
            try:
                import urllib.request
                urllib.request.urlretrieve(url, xz)
                push_log += "[+] descargado %s\n" % name
            except Exception as e:
                return _err("No pude descargar %s (%s). Bajalo manual de github.com/frida/frida/releases" % (name, e))
        # Descomprimir
        try:
            import lzma
            with lzma.open(xz) as f, open(out, "wb") as o:
                o.write(f.read())
            push_log += "[+] descomprimido\n"
        except Exception as e:
            return _err("No pude descomprimir %s: %s" % (xz, e))
        # Subir
        rc, msg, e2 = dynadb.adb(["push", out, "/data/local/tmp/frida-server"], serial)
        push_log += "[+] push: " + (msg or e2 or "").strip() + "\n"
        # chmod y VERIFICAR que se aplico (algunos Nox/BusyBox lo silencian).
        chmod_ok = False
        for attempt in range(3):
            dynadb.adb(["shell", "su", "-c", "chmod 755 /data/local/tmp/frida-server"], serial)
            rc, ls, _ = dynadb.adb(["shell", "ls", "-l", "/data/local/tmp/frida-server"], serial)
            ls = (ls or "").strip()
            if ls.startswith("-rwx"):
                push_log += "[+] chmod 755 OK (%s)\n" % ls.split()[0]
                chmod_ok = True
                break
        if not chmod_ok:
            push_log += "[!] chmod fallo (permisos: %s). Probando arrancar igualmente.\n" % \
                        (ls.split()[0] if ls else "?")

    # 4) Matar TODO frida-server previo (incl. una version vieja de otra sesion que
    # quede ocupando el puerto 27042 -> causa 'ProtocolError: major versions match').
    # No usamos pgrep -f / pkill -x: el toybox de Genymotion no siempre los soporta.
    # Sacamos PIDs con 'ps -A | grep frida-server | awk {PID}' (robusto) + killall.
    _kill_cmd = ("for pid in $(ps -A 2>/dev/null | grep frida-server | grep -v grep | awk '{print $2}'); "
                 "do kill -9 $pid 2>/dev/null; done; "
                 "killall -9 frida-server 2>/dev/null; true")
    for _ in range(2):
        dynadb.adb(["shell", "su", "-c", _kill_cmd], serial)
        time.sleep(0.6)
    # Verificar que no quedo ninguno vivo (si queda, avisar en el log de push)
    rc, alive, _ = dynadb.adb(["shell", "su", "-c",
                               "ps -A 2>/dev/null | grep frida-server | grep -v grep"], serial)
    if (alive or "").strip():
        push_log += "[!] aun quedaba un frida-server vivo; reintentando kill\n"
        dynadb.adb(["shell", "su", "-c", _kill_cmd], serial)
        time.sleep(0.8)
    time.sleep(0.5)
    server_log = ""
    proc = None
    try:
        cmd = [dynadb.ADB] + (["-s", serial] if serial else []) + \
              ["shell", "su", "-c", "/data/local/tmp/frida-server -D"]
        # Capturamos stderr para ver por que cae (si cae). -D = daemonize, pero
        # algunos Toybox/BusyBox su no respetan -D y lo mantienen en fg; capturamos igual.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # Esperar hasta 2.5s a ver si el proceso padre sigue vivo (significa que no
        # daemonizo y probablemente cayo o se quedo pegado). Leemos lo que haya.
        time.sleep(2.0)
        import threading
        out_buf = []
        def reader():
            try:
                for line in iter(proc.stdout.readline, b""):
                    out_buf.append(line.decode("utf-8", "replace").rstrip())
            except Exception:
                pass
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout=0.5)
        server_log = "\n".join(out_buf) if out_buf else ""
    except Exception as e:
        return _err("No pude arrancar frida-server: %s" % e)

    # 5) Verificar y diagnosticar por que no responde (si es el caso)
    ok, ver, err = instrument.server_status(serial)
    diag = ""
    if not ok:
        # Recoger pistas del device para diagnostico
        diag_lines = []
        # a) ¿esta el binario ahi y es ejecutable?
        rc, ls, _ = dynadb.adb(["shell", "ls", "-l", "/data/local/tmp/frida-server"], serial)
        diag_lines.append("ls -l frida-server: %s" % (ls or "(no existe)").strip())
        # b) ¿hay algun frida-server vivo?
        rc, pg, _ = dynadb.adb(["shell", "su", "-c", "pgrep -l frida-server"], serial)
        diag_lines.append("pgrep frida-server: %s" % (pg or "(ninguno)").strip())
        # c) ¿su funciona?
        rc, su, _ = dynadb.adb(["shell", "su", "-c", "id"], serial)
        diag_lines.append("su -c id: %s" % (su or "(fallo)").strip())
        # d) ¿arch del binario vs device?
        rc, filearch, _ = dynadb.adb(["shell", "su", "-c",
                                      "file /data/local/tmp/frida-server 2>/dev/null || readelf -h /data/local/tmp/frida-server 2>/dev/null | head -3"],
                                     serial)
        diag_lines.append("file: %s" % (filearch or "(?)").strip())
        diag_lines.append("device abi: %s (frida-server arch: android-%s)" % (abi, arch))
        # e) ¿version del binario subido?
        rc, sv, _ = dynadb.adb(["shell", "su", "-c",
                                "/data/local/tmp/frida-server --version 2>&1 | head -1"], serial)
        diag_lines.append("frida-server --version: %s" % (sv or "(no arranca)").strip())
        diag_lines.append("frida (venv): %s" % frida_ver)
        if sv and sv.strip() and frida_ver and sv.strip() != frida_ver:
            diag_lines.append("[!] MISMATCH version: server=%s vs venv=%s" %
                              (sv.strip(), frida_ver))
        # f) SELinux?
        rc, se, _ = dynadb.adb(["shell", "getenforce"], serial)
        diag_lines.append("SELinux: %s" % (se or "?").strip())
        # g) stderr capturado al arrancar
        if server_log:
            diag_lines.append("--- stderr del frida-server ---")
            diag_lines.append(server_log)
        diag = "\n".join(diag_lines)

    return _ok({"push_output": push_log, "running": ok, "version": ver or frida_ver,
                "error": err, "diagnostic": diag})


FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_ALT  = "/data/local/fs"   # fallback si /data/local/tmp esta noexec


def _manual_frida_cmds(pkg):
    """Bloque de comandos manuales (los que SI funcionan) para mostrar cuando algo de
    Frida falla en la GUI. Lo mas optimo: si el automatico no resulta, el usuario copia esto."""
    p = pkg or "com.taller.bancoalien"
    return (
        "\n\n=== RECETA QUE SI FUNCIONA (arrancar frida-server + bypass) ===\n"
        "Ejecuta en la carpeta AlienProbe, en este orden:\n"
        "1) MATAR server viejo  (evita 'Address already in use' y 'major versions match'):\n"
        "   platform-tools\\adb shell \"su -c 'killall -9 frida-server'\"\n"
        "2) SUBIR la version correcta (la misma del venv):\n"
        "   .venv\\Scripts\\python setup_frida.py --no-run\n"
        "3) ARRANCAR el server (deja esta ventana abierta):\n"
        "   platform-tools\\adb shell \"su -c '/data/local/tmp/frida-server -D'\"\n"
        "4) CONFIRMAR que responde:\n"
        "   .venv\\Scripts\\frida-ps -U\n"
        "5) BYPASS:  en la GUI pulsa 'Abrir con bypass de root'  (o a mano):\n"
        "   platform-tools\\adb shell \"su -c 'am force-stop %s'\"\n"
        "   .venv\\Scripts\\frida -U -f %s -l frida_scripts\\root_bypass.js\n"
        "(diagnostico opcional:  .venv\\Scripts\\python diag_frida.py)"
        % (p, p)
    )

_FRIDA_KILL_CMD = ("for pid in $(ps -A 2>/dev/null | grep frida-server | grep -v grep | awk '{print $2}'); "
                   "do kill -9 $pid 2>/dev/null; done; killall -9 frida-server 2>/dev/null; true")


def _kill_all_frida(serial=None):
    """Mata TODO frida-server del device (robusto para el toybox de Genymotion: usa
    ps+awk+killall, no pgrep -f/pkill -x que no siempre existen). Reintenta y verifica."""
    for _ in range(2):
        dynadb.adb(["shell", "su", "-c", _FRIDA_KILL_CMD], serial)
        time.sleep(0.5)
    rc, alive, _ = dynadb.adb(["shell", "su", "-c",
                               "ps -A 2>/dev/null | grep frida-server | grep -v grep"], serial)
    return not (alive or "").strip()


def _align_frida_server(serial, frida_ver):
    """Asegura que el BINARIO frida-server del device sea EXACTAMENTE frida_ver.
    Evita el 'ProtocolError: major versions match': si hay un server viejo vivo
    (p.ej. v17 ocupando 27042) lo MATA y sube/deja el binario de la version correcta.
    Devuelve (ok, log)."""
    log = []
    rc, abi, _ = dynadb.adb(["shell", "getprop", "ro.product.cpu.abi"], serial)
    abi = (abi or "").strip()
    arch = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm"}.get(abi)
    if not arch:
        return False, "arch no soportada: %s" % abi
    rc, dv, _ = dynadb.adb(["shell", "su", "-c", "%s --version 2>/dev/null" % FRIDA_SERVER_PATH], serial)
    dv = (dv or "").strip().split()[0] if (dv or "").strip() else ""
    if dv == frida_ver:
        return True, "[i] binario device ya es v%s" % frida_ver
    log.append("[i] binario device=%s != venv=%s -> matando server viejo y re-subiendo" % (dv or "ausente", frida_ver))
    _kill_all_frida(serial)   # el v17 vivo ocupa 27042; hay que matarlo si o si
    name = "frida-server-%s-android-%s" % (frida_ver, arch)
    url = "https://github.com/frida/frida/releases/download/%s/%s.xz" % (frida_ver, name)
    xz = os.path.join(BASE, name + ".xz")
    out = os.path.join(BASE, "frida-server")
    try:
        if not os.path.exists(xz):
            import urllib.request
            urllib.request.urlretrieve(url, xz)
        import lzma
        with lzma.open(xz) as f, open(out, "wb") as o:
            o.write(f.read())
        dynadb.adb(["push", out, FRIDA_SERVER_PATH], serial)
        dynadb.adb(["shell", "su", "-c", "chmod 755 %s" % FRIDA_SERVER_PATH], serial)
        log.append("[+] frida-server v%s subido" % frida_ver)
        return True, "\n".join(log)
    except Exception as e:
        return False, "no pude alinear frida-server: %s" % e


def _ensure_frida_server(serial=None, timeout=14):
    """Garantiza que frida-server corre como root en el device.

    Estrategia:
      - Alinea la version del binario con la del venv (mata server viejo si difiere).
      - Detecta noexec probando '--version' (no basta -rwx). Remonta /data exec
        y, si sigue sin ejecutar, reubica el binario a /data/local/fs.
      - Arranca con el daemonize propio de frida-server (-D).
      - §5.3 Verifica uid=root via instrument.server_status (chip honesto).

    Devuelve (ok, version, err, log). No lanza excepciones. Usado por
    /api/frida/preset para auto-arrancar el server antes del spawn, asi el
    usuario no toca nada manual tras reiniciar el emulador.
    """
    log_lines = []
    # 0) Alinear la VERSION del binario con la del venv. Si hay un server viejo (v17)
    #    vivo ocupando 27042, lo mata aqui -> asi no aparece 'major versions match'.
    try:
        _fv = instrument.frida_version()
        if _fv:
            aligned, alog = _align_frida_server(serial, _fv)
            if alog:
                log_lines.append(alog)
    except Exception as _e:
        log_lines.append("[!] alineacion de version fallo: %s" % _e)

    # 1) Ya corre como root LA VERSION CORRECTA?
    ok, ver, err = instrument.server_status(serial)
    if ok:
        return True, ver, None, "\n".join(log_lines + ["[i] frida-server correcto ya corre como root"])
    log_lines.append("[i] frida-server no responde, arrancando automaticamente...")

    # 2) Existe el binario?
    rc, ls, _ = dynadb.adb(["shell", "ls", "-l", FRIDA_SERVER_PATH], serial)
    ls = (ls or "").strip()
    if not ls or "No such file" in ls or ls.startswith("ls:"):
        return False, None, ("frida-server no esta en %s. "
                            "Pulsa 'Iniciar frida-server' en la GUI para subirlo." % FRIDA_SERVER_PATH
                            ), "\n".join(log_lines)
    log_lines.append("[i] binario: %s" % (ls.split()[0] if ls else "(?)"))

    # 3) chmod 755 (reintentar, verificar -rwx)
    chmod_ok = False
    for _attempt in range(3):
        dynadb.adb(["shell", "su", "-c", "chmod 755 %s" % FRIDA_SERVER_PATH], serial)
        rc, ls2, _ = dynadb.adb(["shell", "ls", "-l", FRIDA_SERVER_PATH], serial)
        if (ls2 or "").startswith("-rwx"):
            chmod_ok = True
            log_lines.append("[+] chmod 755 OK")
            break
    if not chmod_ok:
        log_lines.append("[!] chmod fallo, intentando arrancar igualmente")

    # 4) §5.1 Probar EJECUCION real (no solo permisos). Detecta /data/local/tmp noexec,
    #    causa raiz #1 en Nox: el binario tiene -rwx pero el FS esta montado noexec.
    server_path = FRIDA_SERVER_PATH
    rc, ver_out, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % server_path], serial)
    ver_out = (ver_out or "").strip()
    exec_ok = bool(ver_out) and "denied" not in ver_out.lower() and "not executable" not in ver_out.lower()
    log_lines.append("[i] --version: %s" % (ver_out or "(sin salida)"))
    if not exec_ok:
        log_lines.append("[!] no ejecuta (posible noexec en /data/local/tmp). Remontando /data exec...")
        dynadb.adb(["shell", "su", "-c", "mount -o remount,exec /data"], serial)
        rc, ver_out, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % server_path], serial)
        ver_out = (ver_out or "").strip()
        if not (ver_out and "denied" not in ver_out.lower()):
            # Fallback: reubicar a /data/local/fs (a veces /tmp es noexec pero /data/local no)
            log_lines.append("[!] /data/local/tmp sigue noexec. Reubicando a %s..." % FRIDA_SERVER_ALT)
            dynadb.adb(["shell", "su", "-c",
                        "cp %s %s && chmod 755 %s" % (FRIDA_SERVER_PATH, FRIDA_SERVER_ALT, FRIDA_SERVER_ALT)],
                       serial)
            rc, ver_out2, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % FRIDA_SERVER_ALT], serial)
            ver_out2 = (ver_out2 or "").strip()
            if ver_out2 and "denied" not in ver_out2.lower():
                server_path = FRIDA_SERVER_ALT
                ver_out = ver_out2
                log_lines.append("[+] usando ruta alterna: %s" % server_path)
            else:
                return False, None, ("frida-server no ejecuta (noexec). Ni /data/local/tmp ni %s "
                                    "permiten exec. Prueba un AVD Google APIs o Genymotion "
                                    "(usa Genymotion x86_64, no emuladores ARM)." % FRIDA_SERVER_ALT), "\n".join(log_lines)

    # 5) Matar previos (robusto para toybox: ps+awk+killall, no pgrep -f/pkill -x)
    _kill_all_frida(serial)
    time.sleep(0.5)

    # 6) Arrancar con el daemonize propio de frida-server (-D). Es EXACTAMENTE lo que
    #    funciona a mano; 'setsid ... &' era fragil en Genymotion (toybox no lo respeta
    #    bien y el proceso moria al cerrar el adb shell -> chip 'off').
    try:
        dynadb.adb(["shell", "su", "-c", "%s -D" % server_path], serial, timeout=8)
    except Exception as e:
        # -D no retorna hasta forkear; un timeout aqui suele significar que ya quedo corriendo
        log_lines.append("[i] arranque -D (%s), verificando..." % e)

    # 7) Esperar a que responda como root (polling). server_status verifica uid=0
    #    (§5.3): si responde pero sin root, mata y rearranca (un server sin root
    #    ocupa el 27042 y hace que spawn falle con "jailed").
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        ok, ver, serr = instrument.server_status(serial)
        if ok:
            log_lines.append("[+] frida-server arrancado como root (v%s) en %s" % (ver, server_path))
            return True, ver, None, "\n".join(log_lines)
    return False, None, ("frida-server no arranco tras %ds. Detalle: %s. "
                        "Usa Genymotion x86_64 o un AVD Google APIs (evita emuladores ARM)." %
                        (timeout, (serr or err or "").split("\n")[0])), "\n".join(log_lines)


@app.post("/api/frida/reactivate")
def frida_reactivate():
    """Re-arranca frida-server para el caso "reinicié el emulador".
    Llama a _ensure_frida_server (chmod + noexec + setsid + verify)."""
    serial = STATE.get("serial")
    ok, ver, err, log = _ensure_frida_server(serial)
    return _ok({"running": ok, "version": ver, "error": err, "log": log})


@app.post("/api/devices/select")
def devices_select_v2(serial=None):
    """Wrapper interno: no usado como endpoint, evita redefinir el de arriba."""
    pass


def _bg_ensure_frida(serial):
    """Lanza _ensure_frida_server en un hilo (no bloquea al seleccionar device/app).
    El resultado se ve en el chip 'frida' al refrescar /api/frida/status."""
    def _t():
        try:
            _ensure_frida_server(serial)
        except Exception:
            pass
    threading.Thread(target=_t, daemon=True).start()


_DANGER_PERMS = {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_SMS", "SEND_SMS",
                 "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION",
                 "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "CAMERA", "RECORD_AUDIO",
                 "READ_PHONE_STATE", "READ_CALL_LOG", "WRITE_SETTINGS", "REQUEST_INSTALL_PACKAGES",
                 "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES", "READ_CALENDAR", "BODY_SENSORS"}


def _static_scan(pkg, serial):
    """Quick-scan estático: extrae el APK (si falta) y revisa permisos, exported, flags
    debuggable/allowBackup y secretos/URLs embebidos en el binario."""
    apk = os.path.join(BASE, "loot", pkg + ".apk")
    if not os.path.exists(apk):
        rc, out, _ = dynadb.adb(["shell", "pm", "path", pkg], serial)
        apkpath = ""
        for ln in (out or "").splitlines():
            if ln.startswith("package:"):
                apkpath = ln.split("package:", 1)[1].strip(); break
        if apkpath:
            os.makedirs(os.path.dirname(apk), exist_ok=True)
            dynadb.adb(["pull", apkpath, apk], serial)
    rc, dump, _ = dynadb.adb(["shell", "dumpsys", "package", pkg], serial)
    dump = dump or ""
    debuggable = "DEBUGGABLE" in dump
    allow_backup = "ALLOW_BACKUP" in dump
    perms = []
    for m in re.findall(r'(android\.permission\.[A-Z_]+)', dump):
        if m not in perms:
            perms.append(m)
    dangerous = [p for p in perms if p.split(".")[-1] in _DANGER_PERMS]
    try:
        comps, exported = dynadb.components_data(pkg, serial)
    except Exception:
        exported = []
    urls = set()
    secrets = []
    if os.path.exists(apk):
        try:
            import zipfile
            with zipfile.ZipFile(apk) as z:
                for name in z.namelist():
                    if not (name.endswith(".dex") or name.endswith(".arsc")
                            or name.startswith("assets/") or name.endswith(".xml")):
                        continue
                    try:
                        t = z.read(name).decode("latin-1", "ignore")
                    except Exception:
                        continue
                    for u in re.findall(r'https?://[\w.\-/:%?#\[\]@!$&\'()*+,;=~]+', t):
                        if len(urls) < 80:
                            urls.add(u)
                    for fl in re.findall(r'ALIEN\{[^}]{1,60}\}', t):
                        secrets.append(["flag", fl])
                    for k in re.findall(r'(?i)(api[_-]?key|secret|passwd|password|token)["\':=\s]{1,4}([A-Za-z0-9_\-]{8,40})', t)[:20]:
                        secrets.append([k[0], k[1]])
        except Exception:
            pass
    # dedup secrets
    seen = set(); ded = []
    for t, v in secrets:
        if (t, v) not in seen:
            seen.add((t, v)); ded.append([t, v])
    return {"apk": apk if os.path.exists(apk) else None, "debuggable": debuggable,
            "allow_backup": allow_backup, "permissions": perms, "dangerous": dangerous,
            "exported": sorted(exported), "urls": sorted(urls)[:60], "secrets": ded[:40]}


_STORAGE_SNAP = {}   # pkg -> {ruta: md5}  (baseline para el diff de almacenamiento)


def _storage_snapshot(pkg, serial, mode):
    """Devuelve {ruta_relativa: md5} de los archivos del sandbox (sin cache)."""
    base = "/data/data/%s" % pkg
    if mode == "root":
        cmd = ["exec-out", "su", "-c",
               "find %s -type f -not -path '*/cache/*' -exec md5sum {} + 2>/dev/null" % base]
    else:
        cmd = ["exec-out", "run-as", pkg, "sh", "-c",
               "find . -type f -not -path './cache/*' -exec md5sum {} + 2>/dev/null"]
    rc, out, _ = dynadb.adb(cmd, serial)
    snap = {}
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(None, 1)
        if len(parts) != 2:
            continue
        h, p = parts
        if mode == "root":
            key = p.replace(base + "/", "")
        else:
            key = p[2:] if p.startswith("./") else p
        snap[key] = h
    return snap


def _build_hook_js(cls, method, force=""):
    """Genera un script Frida que hookea cls.method: registra args/retorno y,
    si `force` no está vacío, fuerza el valor de retorno (true/false, número, texto o null)."""
    if not force:
        ret_expr = "ov.apply(this, arguments)"
        forced_tag = ""
    elif force.lower() in ("true", "false"):
        ret_expr = force.lower(); forced_tag = ' + " (FORZADO)"'
    elif re.fullmatch(r"-?\d+", force):
        ret_expr = force; forced_tag = ' + " (FORZADO)"'
    elif force.lower() == "null":
        ret_expr = "null"; forced_tag = ' + " (FORZADO)"'
    else:
        ret_expr = json.dumps(force); forced_tag = ' + " (FORZADO)"'
    C = json.dumps(cls); M = json.dumps(method)
    return (
        "Java.perform(function () {\n"
        "  try {\n"
        "    var K = Java.use(%s);\n" % C +
        "    var target = K[%s];\n" % M +
        "    if (!target) { console.log('[hook] metodo no encontrado: ' + %s); return; }\n" % M +
        "    target.overloads.forEach(function (ov) {\n"
        "      ov.implementation = function () {\n"
        "        var a = [];\n"
        "        for (var i = 0; i < arguments.length; i++) { try { a.push('' + arguments[i]); } catch (e) { a.push('?'); } }\n"
        "        console.log('[hook] ' + %s + '.' + %s + '(' + a.join(', ') + ')');\n" % (C, M) +
        "        var ret = %s;\n" % ret_expr +
        "        console.log('[hook]   -> ' + ret%s);\n" % forced_tag +
        "        return ret;\n"
        "      };\n"
        "    });\n"
        "    console.log('[hook] instalado en ' + %s + '.' + %s + ' (' + target.overloads.length + ' overload(s))');\n" % (C, M) +
        "  } catch (e) { console.log('[hook] error: ' + e); }\n"
        "});\n"
    )


def _providers(pkg, serial=None):
    """Enumera las 'authorities' de ContentProviders de la app (best-effort, varias fuentes)."""
    auths = []
    rc, out, _ = dynadb.adb(["shell", "dumpsys", "package", "providers"], serial)
    cur = None
    for ln in (out or "").splitlines():
        s = ln.strip()
        m = re.match(r'^([A-Za-z0-9_.\-]+):$', s)
        if m:
            cur = m.group(1)
            continue
        if "Provider{" in s and pkg in s and cur:
            auths.append(cur)
            cur = None
    if not auths:  # fallback: dump del paquete
        rc, out2, _ = dynadb.adb(["shell", "dumpsys", "package", pkg], serial)
        for ln in (out2 or "").splitlines():
            m = re.search(r'authority=([A-Za-z0-9_.\-;]+)', ln)
            if m:
                auths += m.group(1).split(";")
    seen = []
    for a in auths:
        if a and a not in seen:
            seen.append(a)
    return seen


@app.post("/api/frida/preset")
def frida_preset():
    """Ejecuta un preset {id, params}. Devuelve {session_id} o el resultado core."""
    body = request.json or {}
    pid = body.get("id", "").strip()
    params = body.get("params", {}) or {}
    preset = find_preset(pid)
    if not preset:
        return _err("preset no encontrado: %s" % pid)
    pkg = STATE.get("package")
    if not pkg:
        return _err("Selecciona una app (target) primero")
    serial = STATE.get("serial")
    ptype = preset.get("type", "attach")

    # Chequeo previo para presets que usan FRIDA (spawn/attach/custom):
    # auto-arrancar frida-server como root si no responde (asi el usuario
    # no tiene que tocar nada manual tras reiniciar el emulador).
    is_frida = ptype in ("spawn", "attach") or (ptype == "custom" and
                                                preset.get("action") != "core_action")
    if is_frida:
        ok, ver, serr = instrument.server_status(serial)
        if not ok:
            # Auto-arrancar frida-server (chmod + noexec + setsid + verify).
            # autolog lleva el diagnostico (permisos, --version, ruta, noexec)
            # que se reenvia a la consola en vivo para que el usuario vea el POR QUE.
            ok, ver, serr, autolog = _ensure_frida_server(serial)
            if not ok:
                hint = ("frida-server no pudo arrancar automaticamente. "
                        "Detalle: " + (serr or "").split("\n")[0] +
                        "\n\nLog de arranque:\n" + (autolog or ""))
                return _err(hint + _manual_frida_cmds(pkg))
            # Propagar el log de arranque a la consola de la GUI (didactico)
            if autolog:
                print("[frida-server] %s" % autolog)

    # Tipos CORE: no usan frida, ejecutan acciones del nucleo
    if ptype == "core":
        action = preset.get("action")
        if action == "storage":
            res = dynadb.storage_data(pkg, serial, outdir=os.path.join(BASE, "loot"),
                                     mode=STATE.get("mode", "auto"))
            return _ok({"action": "storage", "result": res})
        if action == "screenshot":
            rc, data, err = dynadb.adb(["exec-out", "screencap", "-p"], serial, binary=True)
            if rc == 0 and data[:8] == b"\x89PNG\r\n\x1a\n":
                b64 = base64.b64encode(data).decode("ascii")
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join(BASE, "loot", "screenshot_%s.png" % ts)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "wb").write(data)
                report_log.log_action("screenshot", pkg,
                    evidencia="Captura guardada: %s" % path, extra={"img_path": path})
                return _ok({"action": "screenshot", "png_base64": b64, "saved": path})
            return _err((err or "formato inesperado").strip())
        if action == "data_tree":
            mode = access.get_access_mode(pkg, serial, prefer=STATE.get("mode", "auto"))
            if mode == "none":
                return _err("Sin acceso (root/run-as) para listar /data/data")
            if mode == "root":
                rc, out, err = dynadb.adb(["exec-out", "su", "-c",
                                           "ls -R /data/data/%s" % pkg], serial)
            else:
                rc, out, err = dynadb.adb(["exec-out", "run-as", pkg, "ls", "-R"], serial)
            return _ok({"action": "data_tree", "mode": mode, "tree": out})
        if action == "launch":
            activity = params.get("activity", "").strip()
            ek = params.get("extra_key", "").strip()
            ev = params.get("extra_val", "").strip()
            if not activity:
                return _err("Falta el activity (parametro 'activity')")
            args = ["shell", "am", "start", "-n", "%s/%s" % (pkg, activity)]
            if ek and ev:
                # numeros -> --ei (int), texto -> --es (string). Asi el IDOR con accountId funciona.
                if re.fullmatch(r"-?\d+", ev):
                    args += ["--ei", ek, ev]
                else:
                    args += ["--es", ek, ev]
            rc, out, err = dynadb.adb(args, serial)
            blob = (out + err).strip()
            verdict = "ok" if (rc == 0 and "Starting" in blob) else \
                      ("denied" if "Permission Denial" in blob else "unknown")
            return _ok({"action": "launch", "rc": rc, "output": blob, "verdict": verdict})
        if action == "audit":
            return _run_audit(pkg, serial)
        if action == "deep_link":
            uri = params.get("uri", "").strip()
            if not uri:
                return _err("Falta la URI del deep link")
            rc, out, err = dynadb.adb(["shell", "am", "start", "-W", "-a",
                                       "android.intent.action.VIEW", "-d", uri, pkg], serial)
            return _ok({"action": "deep_link", "output": (out + err).strip()})
        if action == "app_logs":
            rc, pidout, _ = dynadb.adb(["shell", "pidof", "-s", pkg], serial)
            pidn = (pidout or "").strip()
            if pidn:
                rc, out, _ = dynadb.adb(["logcat", "-d", "--pid", pidn, "-t", "400"], serial)
            else:
                rc, out, _ = dynadb.adb(["logcat", "-d", "-t", "2000"], serial)
                key = pkg.split(".")[-1]
                out = "\n".join(l for l in out.splitlines() if key.lower() in l.lower())
            return _ok({"action": "app_logs", "logs": out.strip()})
        if action == "pull_apk":
            rc, out, _ = dynadb.adb(["shell", "pm", "path", pkg], serial)
            apkpath = ""
            for ln in (out or "").splitlines():
                if ln.startswith("package:"):
                    apkpath = ln.split("package:", 1)[1].strip(); break
            if not apkpath:
                return _err("No encontre la ruta del APK")
            dest = os.path.join(BASE, "loot", pkg + ".apk")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            rc, o, e = dynadb.adb(["pull", apkpath, dest], serial)
            return _ok({"action": "pull_apk", "apk_device": apkpath, "saved": dest, "out": (o + e).strip()})
        if action == "signature_info":
            rc, out, _ = dynadb.adb(["shell", "dumpsys", "package", pkg], serial)
            lines = [l.strip() for l in (out or "").splitlines()
                     if ("sign" in l.lower() or "cert" in l.lower())][:25]
            return _ok({"action": "signature_info", "info": "\n".join(lines) or "sin datos"})
        if action == "providers":
            auths = _providers(pkg, serial)
            uri = (params.get("uri") or "").strip()
            rows = ""
            if uri:
                rc, out, err = dynadb.adb(["shell", "content", "query", "--uri", uri], serial)
                rows = (out + err).strip() or "(sin filas o acceso denegado)"
            if auths or (uri and "denied" not in rows.lower() and "sin filas" not in rows.lower()):
                ev = "Authorities:\n" + "\n".join(auths[:25])
                if uri:
                    ev += "\n\ncontent query --uri %s:\n%s" % (uri, rows[:800])
                report_log.log_action("providers", pkg, evidencia=ev)
            return _ok({"action": "providers", "providers": auths,
                        "query": {"uri": uri, "rows": rows}})
        if action == "storage_diff":
            mode = access.get_access_mode(pkg, serial, prefer=STATE.get("mode", "auto"))
            if mode == "none":
                return _err("Sin acceso (root/run-as) para leer /data/data")
            fase = (params.get("fase") or "antes").strip().lower()
            snap = _storage_snapshot(pkg, serial, mode)
            if fase.startswith("a"):   # antes
                _STORAGE_SNAP[pkg] = snap
                return _ok({"action": "storage_diff", "phase": "antes", "count": len(snap)})
            base = _STORAGE_SNAP.get(pkg)
            if base is None:
                return _err("Primero toma el snapshot 'antes' (fase=antes), luego haz la acción y corre 'despues'.")
            added = sorted(p for p in snap if p not in base)
            removed = sorted(p for p in base if p not in snap)
            changed = sorted(p for p in snap if p in base and snap[p] != base[p])
            if added or changed:
                report_log.log_action("storage_diff", pkg,
                    evidencia="Nuevos:\n" + "\n".join(added[:15]) +
                              "\nModificados:\n" + "\n".join(changed[:15]))
            return _ok({"action": "storage_diff", "phase": "despues",
                        "added": added, "removed": removed, "changed": changed})
        if action == "static_scan":
            res = _static_scan(pkg, serial)
            if res.get("debuggable"):
                report_log.log_action("debuggable", pkg, evidencia="Flag DEBUGGABLE presente en el paquete")
            if res.get("allow_backup"):
                report_log.log_action("allow_backup", pkg, evidencia="Flag ALLOW_BACKUP presente (respaldo adb posible)")
            if res.get("secrets") or res.get("urls"):
                ev = "Secretos en el binario:\n" + "\n".join("[%s] %s" % (t, v) for t, v in res["secrets"][:15])
                ev += "\nURLs:\n" + "\n".join(res["urls"][:15])
                report_log.log_action("static_scan", pkg, evidencia=ev)
            res["action"] = "static_scan"
            return _ok(res)
        return _err("accion core desconocida: %s" % action)

    # Tipos CUSTOM: combinan frida + core
    if ptype == "custom":
        action = preset.get("action")
        if action == "capture_traffic":
            return _capture_traffic(pkg, serial, params, preset)
        if action == "hook_builder":
            cls = (params.get("class") or "").strip()
            method = (params.get("method") or "").strip()
            force = (params.get("force") or "").strip()
            if not cls or not method:
                return _err("Indica la clase (FQCN) y el método a hookear")
            js = _build_hook_js(cls, method, force)
            sid, err = instrument.run_inline(pkg, js, mode="attach", serial=serial)
            if err:
                return _err(err + _manual_frida_cmds(pkg))
            report_log.log_action("hook_builder", pkg,
                evidencia="Hook %s.%s%s" % (cls, method, (" -> retorno forzado a '%s'" % force) if force else " (registro de args/retorno)"))
            sess = instrument.get_session(sid)
            if sess:
                sess["buffer"].insert(0, "[i] hook a la carta -> %s.%s%s" %
                                      (cls, method, (" (forzar %s)" % force) if force else ""))
            return _ok({"session_id": sid})
        if action == "custom_script":
            name = params.get("script_name", "").strip()
            inline = params.get("inline", "").strip()
            mode = params.get("mode", "attach").strip() or "attach"
            if inline:
                sid, err = instrument.run_inline(pkg, inline, mode=mode,
                                                 params=params, serial=serial)
            elif name:
                if mode == "spawn":
                    sid, err = instrument.spawn_with_scripts(pkg, [name],
                                                              params=params, serial=serial)
                else:
                    sid, err = instrument.attach_with_scripts(pkg, [name],
                                                                params=params, serial=serial)
            else:
                return _err("Indica un script de la libreria o pega JS")
            if err:
                return _err(err)
            return _ok({"session_id": sid})
        return _err("accion custom desconocida: %s" % action)

    # Tipos Frida (spawn/attach) con scripts del catalogo
    scripts = preset.get("scripts", [])
    inline_js = preset.get("inline_js")
    # Si el preset define inline_js (ej. enum_classes), lo usamos como script extra
    sources = []
    for s in scripts:
        sources.append(s)
    if inline_js:
        # inline_js es una plantilla con placeholders; se aplica params
        sources.append(("<inline>", instrument._apply_params(inline_js, params)))

    # method_trace: necesita reescribir la variable CLASE del script
    if pid == "method_trace" and params.get("class"):
        # Sobrescribimos la primera linea del script con la clase pedida
        name = scripts[0] if scripts else "method_trace.js"
        src, err = instrument._read_script(name)
        if src:
            # Reemplazar la linea "var CLASE = ..."
            lines = src.splitlines()
            for i, ln in enumerate(lines):
                if ln.startswith("var CLASE"):
                    lines[i] = 'var CLASE = "%s";' % params["class"]
                    break
            sources = [("<method_trace>", "\n".join(lines))]

    if ptype == "spawn":
        # Convertir sources a tuplas (name, source)
        tuples = []
        for s in sources:
            if isinstance(s, tuple):
                tuples.append(s)
            else:
                src, err = instrument._read_script(s)
                if err:
                    return _err(err)
                tuples.append((s, instrument._apply_params(src, params)))
        sid, err = instrument.spawn_with_scripts(pkg, tuples, params=params, serial=serial)
        if err and ("jailed" in err.lower() or "gadget" in err.lower()):
            # Auto-sanacion: frida-server no estaba root (ej. tras reiniciar el emulador).
            _ensure_frida_server(serial)
            time.sleep(1.0)
            sid, err = instrument.spawn_with_scripts(pkg, tuples, params=params, serial=serial)
    else:
        tuples = []
        for s in sources:
            if isinstance(s, tuple):
                tuples.append(s)
            else:
                src, err = instrument._read_script(s)
                if err:
                    return _err(err)
                tuples.append((s, instrument._apply_params(src, params)))
        sid, err = instrument.attach_with_scripts(pkg, tuples, params=params, serial=serial)
        if err and ("jailed" in err.lower() or "gadget" in err.lower()):
            _ensure_frida_server(serial)
            time.sleep(1.0)
            sid, err = instrument.attach_with_scripts(pkg, tuples, params=params, serial=serial)
    if err:
        return _err(err + _manual_frida_cmds(pkg))
    # Inyectar en el buffer de la sesion un resumen de lo que se ejecuto (visible en consola)
    sess = instrument.get_session(sid)
    if sess:
        script_names = [t[0] if isinstance(t, tuple) else t for t in tuples]
        sess["buffer"].insert(0, "[i] preset=%s  pkg=%s  mode=%s  scripts=[%s]" %
                             (pid, pkg, ptype, ", ".join(script_names)))
    # Registrar en el informe acumulativo (si el preset esta en el catalogo)
    if pid in report_log.CATALOG:
        report_log.log_action(pid, pkg,
            evidencia="Preset '%s' ejecutado (%s). Sesión Frida: %s" % (pid, ptype, sid))
    return _ok({"session_id": sid, "pkg": pkg, "scripts": [t[0] if isinstance(t, tuple) else t for t in tuples]})


@app.get("/api/frida/output")
def frida_output():
    sid = (request.args.get("session") or "").strip()
    since = int(request.args.get("since", 0))
    if not sid:
        return _err("Falta ?session=")
    lines, next_idx, status = instrument.drain(sid, since)
    return _ok({"lines": lines, "next": next_idx, "status": status})


@app.get("/api/frida/stream")
def frida_stream():
    """SSE: text/event-stream. El cliente mantiene abierto y recibe lineas nuevas."""
    sid = (request.args.get("session") or "").strip()
    if not sid:
        return _err("Falta ?session=")

    def gen():
        idx = 0
        # 30 minutos max por si acaso
        end = time.time() + 1800
        while time.time() < end:
            lines, idx, status = instrument.drain(sid, idx)
            for ln in lines:
                # SSE: cada evento es "data: <json>\n\n"
                yield "data: %s\n\n" % json.dumps({"line": ln})
            if status in ("stopped", "detached", "error", "missing"):
                yield "data: %s\n\n" % json.dumps({"status": status, "end": True})
                yield "event: end\ndata: {}\n\n"
                break
            time.sleep(0.5)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/frida/stop")
def frida_stop():
    sid = (request.json or {}).get("session", "").strip()
    if not sid:
        return _err("Falta session")
    ok, err = instrument.stop_session(sid)
    if err:
        return _err(err)
    return _ok({"stopped": True})


@app.get("/api/frida/sessions")
def frida_sessions():
    # Auto-limpieza de sesiones viejas/detenidas (>30min o no running)
    instrument.cleanup_sessions(max_age=1800)
    return _ok(instrument.list_sessions())


@app.post("/api/traffic/stop")
def traffic_stop():
    """Quita el proxy del device y detiene mitmproxy si esta corriendo."""
    _set_adb()
    serial = STATE.get("serial")
    # 1) quitar proxy del dispositivo
    dynadb.adb(["shell", "settings", "put", "global", "http_proxy", ":0"], serial)
    # 2) matar mitmproxy si lo arrancamos nosotros
    proc = STATE.pop("mitm_proc", None)
    mitm_killed = False
    if proc:
        try:
            proc.terminate()
            try: proc.wait(timeout=3)
            except Exception: proc.kill()
            mitm_killed = True
        except Exception:
            pass
    return _ok({"proxy_cleared": True, "mitm_killed": mitm_killed})


# ---------------- helpers internos v3 ----------------
def _run_audit(pkg, serial):
    """Auditoria completa: recon + componentes + storage + captura + informe."""
    outdir = os.path.join(BASE, "loot", pkg)
    os.makedirs(outdir, exist_ok=True)
    # 1) recon
    info = dynadb.info_data(pkg, serial) or {}
    # 2) componentes
    comps, exported = dynadb.components_data(pkg, serial)
    # 3) storage
    storage = dynadb.storage_data(pkg, serial, outdir=os.path.join(BASE, "loot"),
                                  mode=STATE.get("mode", "auto"))
    # 4) captura
    shot = os.path.join(outdir, "pantalla.png")
    rc, data, _ = dynadb.adb(["exec-out", "screencap", "-p"], serial, binary=True)
    if rc == 0 and data[:8] == b"\x89PNG\r\n\x1a\n":
        open(shot, "wb").write(data)
    # 5) informe MD reusando cmd_report
    import argparse
    ns = argparse.Namespace(package=pkg, serial=serial, out=os.path.join(BASE, "loot"))
    dynadb.cmd_report(ns)
    md_path = os.path.join(outdir, "informe.md")
    content = open(md_path, encoding="utf-8").read() if os.path.exists(md_path) else ""
    return jsonify({
        "ok": True, "data": {
            "info": info, "components": sorted(comps), "exported": sorted(exported),
            "findings": storage.get("findings", []),
            "report_path": md_path, "report": content,
            "screenshot": shot if os.path.exists(shot) else None,
        }
    })


def _capture_traffic(pkg, serial, params, preset):
    """Captura de trafico: configura proxy en el device + arranca mitmproxy + aplica ssl_unpin.
    Best-effort: si mitmproxy no esta en el venv, devuelve instrucciones."""
    host = params.get("proxy_host", "127.0.0.1").strip() or "127.0.0.1"
    port = str(params.get("proxy_port", "8080")).strip() or "8080"
    # 1) fijar proxy en el dispositivo (settings global http_proxy)
    dynadb.adb(["shell", "settings", "put", "global", "http_proxy", "%s:%s" % (host, port)], serial)
    # 2) arrancar mitmproxy en background (si esta disponible en el venv)
    venv_bin = os.path.join(BASE, ".venv", "Scripts") if os.name == "nt" else os.path.join(BASE, ".venv", "bin")
    mitm = os.path.join(venv_bin, "mitmdump.exe" if os.name == "nt" else "mitmdump")
    proc = None
    if os.path.exists(mitm):
        try:
            logpath = os.path.join(BASE, "logs", "mitm.log")
            os.makedirs(os.path.dirname(logpath), exist_ok=True)
            proc = subprocess.Popen([mitm, "--listen-port", port, "-w", os.path.join(BASE, "loot", "traffic.flow")],
                                    stdout=open(logpath, "a"), stderr=subprocess.STDOUT)
            STATE["mitm_proc"] = proc
        except Exception as e:
            return _err("No pude arrancar mitmproxy: %s" % e)
    else:
        # mitmproxy ausente: devolvemos instrucciones pero seguimos con el bypass
        pass
    # 3) aplicar ssl_unpin via frida (attach)
    scripts = preset.get("scripts", ["ssl_unpin.js"])
    sid, err = instrument.attach_with_scripts(pkg, scripts, params=params, serial=serial)
    result = {"proxy_set": "%s:%s" % (host, port), "mitm_started": proc is not None,
              "mitm_path": mitm if os.path.exists(mitm) else None}
    if err:
        result["frida_error"] = err
    else:
        result["session_id"] = sid
    return _ok(result)


# ---------------- SPA ----------------
@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")

@app.get("/<path:p>")
def static_files(p):
    return send_from_directory(BASE, p)


def open_browser(url):
    def _o():
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Timer(0.8, _o).start()


def main():
    ap = argparse.ArgumentParser(description="AlienProbe GUI (0xAlienSec)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    url = "http://%s:%d" % (args.host, args.port)
    print("=" * 60)
    print("  AlienProbe · 0xAlienSec  -  http://%s:%d" % (args.host, args.port))
    print("  Ctrl+C para salir.")
    print("=" * 60)
    if not args.no_browser:
        open_browser(url)
    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n[i] Saliendo.")


if __name__ == "__main__":
    main()