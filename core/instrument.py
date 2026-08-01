# -*- coding: utf-8 -*-
"""
core/instrument.py - Wrapper de Frida (bindings Python) para AlienProbe v3.

Expone sesiones de instrumentacion que se controlan desde la GUI:
  - spawn_with_scripts(pkg, [scripts])  -> spawnea la app cargando scripts ANTES del resume
  - attach_with_scripts(pkg, [scripts]) -> se engancha a la app ya abierta
  - list_sessions() / get_session(id) / stop_session(id)
  - drain(id) -> devuelve y vacia el buffer de mensajes pendientes (para polling/SSE)

Cada sesion guarda:
  {id, pkg, mode: spawn|attach, scripts:[...], status: running|detached|error,
   buffer:[lineas], device, pid, frida_session, frida_script}

No reimprime logica de adb: solo usa frida. Si frida no esta disponible, las funciones
devuelven un error claro (la GUI lo muestra y sugiere setup_frida).
"""
import os
import sys
import threading
import uuid
import time
import json
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE, "frida_scripts")

try:
    import frida
    _HAS_FRIDA = True
except Exception:
    frida = None
    _HAS_FRIDA = False

# Registro de sesiones en memoria (id -> dict)
_SESSIONS = {}
_LOCK = threading.Lock()


def has_frida():
    return _HAS_FRIDA


# Patrones de errores conocidos de Frida -> (causa, fix)
_FRIDA_ERROR_HINTS = [
    ("need Gadget to attach on jailed Android",
     "frida-server no corre como root (o el device no esta rooteado)",
     "1) adb shell su -c '/data/local/tmp/frida-server -D &'  (como root)\n"
     "   2) si el emulador no es root (Nox/MEmu): activa root en sus opciones\n"
     "   3) en la GUI: pestana Frida -> 'Iniciar frida-server' (lo sube y arranca con su)"),
    ("unable to connect to remote frida-server",
     "frida-server no responde en el device (no arrancado o cayo al instante)",
     "1) adb shell su -c '/data/local/tmp/frida-server -D &' \n"
     "   2) si cae al arrancar: arch o version mismatch. Corre setup_frida.py otra vez\n"
     "   3) GUI: pestana Frida -> 'Verificar frida-server' luego 'Iniciar frida-server'"),
    ("device not found",
     "frida no ve el device (adb desconectado o serial mal)",
     "1) adb devices  (¿aparece el emulador?)\n"
     "   2) GUI: boton 'Auto (Nox...)' o 'Conectar' con host:port correcto\n"
     "   3) despues: pestana Frida -> 'Iniciar frida-server'"),
    ("frida-server",
     "frida-server no responde en el device",
     "1) adb shell su -c '/data/local/tmp/frida-server -D &' \n"
     "   2) GUI: pestana Frida -> 'Iniciar frida-server'"),
    ("process not found",
     "la app no esta corriendo (attach necesita que este abierta)",
     "Abre la app primero (manualmente) y luego attach. Si quieres spawn (arrancar hookeada), usa un preset tipo spawn."),
    ("failed to spawn",
     "spawn fallo (paquete inexistente o frida-server sin permisos)",
     "1) verifica el paquete: adb shell pm list packages | grep <pkg>\n"
     "   2) frida-server debe correr como root (su -c)\n"
     "   3) device debe estar rooteado"),
    ("unable to load script",
     "el script JS de frida tiene error de sintaxis o usa API inexistente",
     "Revisa el script en frida_scripts/. El error suele ser version de frida incompat."),
]


def _diagnose(exc):
    """Devuelve un string multilinea con tipo, mensaje y diagnostico (causa+fix)."""
    etype = exc.__class__.__name__
    msg = str(exc)
    causa = fix = None
    for needle, c, f in _FRIDA_ERROR_HINTS:
        if needle.lower() in msg.lower():
            causa, fix = c, f
            break
    if not causa:
        # Fallback generico pero con contexto
        causa = "excepcion no reconocida de frida"
        fix = ("1) revisa que frida-server corra como root: adb shell su -c "
               "'/data/local/tmp/frida-server -D &'\n"
               "   2) verifica version de frida (Python) vs frida-server (deben coincidir)\n"
               "   3) si persiste, reporta el tipo de excepcion arriba")
    return ("[tipo] %s\n[mensaje] %s\n[causa] %s\n[fix]\n%s"
            % (etype, msg, causa, fix))


def _short_err(exc):
    """Version corta (una linea) para devolver al caller y mostrar en GUI/CLI."""
    return _diagnose(exc)


def frida_version():
    return frida.__version__ if _HAS_FRIDA else None


def _device(serial=None):
    """Device de frida. PREFIERE get_usb_device() (lo que usa 'frida -U', que SI permite
    spawn con frida-server como root). El transporte 'remote'/emparejado por serial puede
    devolver un device que spawn trata como 'jailed'."""
    if not _HAS_FRIDA:
        return None, "frida no esta instalado en este Python. Ejecuta setup_frida.py con el venv."
    # 1) USB/adb automatico: el camino que funciona para spawn (equivalente a 'frida -U')
    try:
        return frida.get_usb_device(timeout=5), None
    except Exception:
        pass
    # 2) Emparejar por serial en los devices enumerados (transporte adb)
    if serial:
        try:
            mgr = frida.get_device_manager()
            for d in mgr.enumerate_devices():
                if d.id == serial or serial in d.id:
                    return d, None
            # 3) ultimo recurso: device remoto por TCP al frida-server (host:27042)
            if ":" in serial:
                host = serial.split(":")[0]
                try:
                    return mgr.add_remote_device("%s:27042" % host), None
                except Exception:
                    pass
        except Exception as e:
            return None, "No pude obtener device frida: %s" % e
    return None, ("No encontre el device USB de frida. ¿frida-server corre en el device "
                  "(puerto 27042) y hay un solo emulador conectado?")


def _read_script(name):
    """Lee un script de frida_scripts/<name>. Devuelve (source, err)."""
    # Acepta nombre relativo o ruta
    if os.path.isabs(name):
        p = name
    else:
        p = os.path.join(SCRIPTS_DIR, name)
    if not os.path.exists(p):
        return None, "Script no encontrado: %s" % p
    try:
        return open(p, encoding="utf-8").read(), None
    except Exception as e:
        return None, "No pude leer %s: %s" % (p, e)


def _apply_params(source, params):
    """Reemplaza placeholders %KEY% por valores de params."""
    if not params:
        return source
    out = source
    for k, v in params.items():
        out = out.replace("%%%s%%" % k.upper(), str(v))
    return out


def _on_message(session_id):
    """Devuelve un handler para script.on('message') que appenda al buffer.
    Frida envia 3 tipos de mensajes:
      - type='log'   level=info/warning/error  payload='texto'  (console.log/warn/error)
      - type='error' description='...' stack='...'             (excepciones del script)
      - type='send'  payload=...                              (script.send())
    """
    def handler(message, data):
        with _LOCK:
            sess = _SESSIONS.get(session_id)
            if not sess:
                return
            if not isinstance(message, dict):
                sess["buffer"].append(str(message))
                return
            mtype = message.get("type")
            if mtype == "log":
                # console.log / console.warn / console.error del script JS
                level = message.get("level", "info")
                payload = message.get("payload", "")
                tag = {"info": "", "warning": "[warn] ", "error": "[error] "}.get(level, "")
                sess["buffer"].append(tag + str(payload))
            elif mtype == "error":
                desc = message.get("description", "")
                stack = message.get("stack", "")
                sess["buffer"].append("[error] %s%s" % (desc, ("\n" + stack) if stack else ""))
            elif mtype == "send":
                payload = message.get("payload", "")
                if isinstance(payload, (dict, list)):
                    sess["buffer"].append(json.dumps(payload, default=str))
                else:
                    sess["buffer"].append(str(payload))
            else:
                # Cualquier otro tipo: serializar
                sess["buffer"].append(json.dumps(message, default=str))
            # Limitar buffer
            if len(sess["buffer"]) > 5000:
                sess["buffer"] = sess["buffer"][-5000:]
    return handler


def _make_log_handler(session_id):
    """Handler para script.set_log_handler(): captura console.log/warn/error del script
    JS y lo mete al buffer de la sesion. SIN esto, Frida manda esos logs a su handler por
    defecto (stdout/terminal) y NUNCA llegan a la consola de la GUI. Esta era la causa de
    'no aparece ningun [root] ...' en la interfaz."""
    def on_log(level, text):
        with _LOCK:
            sess = _SESSIONS.get(session_id)
            if not sess:
                return
            tag = {"info": "", "warning": "[warn] ", "error": "[error] "}.get(level, "")
            sess["buffer"].append(tag + str(text))
            if len(sess["buffer"]) > 5000:
                sess["buffer"] = sess["buffer"][-5000:]
    return on_log


def _wire_script(sc, sid):
    """Conecta el script a los buffers: mensajes send()/error Y console.log."""
    sc.on("message", _on_message(sid))
    try:
        sc.set_log_handler(_make_log_handler(sid))   # <-- clave para ver console.log en la GUI
    except Exception:
        pass


def spawn_with_scripts(pkg, scripts, params=None, serial=None):
    """
    Spawnea <pkg> y carga los scripts FRIDA antes del resume (para bypass temprano).
    scripts: lista de rutas relativas a frida_scripts/ (o absolutas) o tuplas (name, source).
    Devuelve (session_id, err).
    """
    if not _HAS_FRIDA:
        return None, "frida no disponible"
    dev, err = _device(serial)
    if err:
        return None, err
    # force-stop previo: evita enganchar una instancia vieja ya abierta (con el dialogo de root).
    try:
        import dynadb
        dynadb.adb(["shell", "am", "force-stop", pkg], serial)
    except Exception:
        pass
    try:
        pid = dev.spawn([pkg])
    except Exception as e:
        return None, "spawn fallo:\n" + _short_err(e)
    return _attach_and_load(dev, pid, pkg, scripts, params, serial, mode="spawn")


def attach_with_scripts(pkg, scripts, params=None, serial=None):
    """Se engancha a la app ya abierta (debe estar corriendo). Devuelve (session_id, err)."""
    if not _HAS_FRIDA:
        return None, "frida no disponible"
    dev, err = _device(serial)
    if err:
        return None, err
    try:
        pid = dev.get_process(pkg).pid
    except Exception as e:
        return None, ("No encontre el proceso '%s':\n" % pkg) + _short_err(e)
    return _attach_and_load(dev, pid, pkg, scripts, params, serial, mode="attach")


def _attach_and_load(dev, pid, pkg, scripts, params, serial, mode):
    sid = uuid.uuid4().hex[:12]
    sess_dict = {
        "id": sid, "pkg": pkg, "mode": mode, "scripts": list(scripts or []),
        "status": "running", "buffer": [], "device": getattr(dev, "id", None),
        "pid": pid, "frida_session": None, "frida_script": None, "serial": serial,
        "started_at": time.time(),
    }
    with _LOCK:                       # FIX: registrar ANTES de load/resume para no perder console.log
        _SESSIONS[sid] = sess_dict
    try:
        fs = dev.attach(pid)
    except Exception as e:
        sess_dict["status"] = "error"
        sess_dict["buffer"].append("[error] attach fallo:\n" + _short_err(e))
        with _LOCK:
            _SESSIONS[sid] = sess_dict
        return sid, "attach fallo:\n" + _short_err(e)
    sess_dict["frida_session"] = fs

    # Cargar cada script
    sources = []
    for s in (scripts or []):
        if isinstance(s, tuple) and len(s) == 2:
            name, src = s
        else:
            name = s if isinstance(s, str) else str(s)
            src, err = _read_script(name)
            if err:
                sess_dict["buffer"].append("[error] %s" % err)
                continue
        sources.append((name, _apply_params(src, params or {})))

    if not sources:
        sess_dict["buffer"].append("[warn] no se cargo ningun script (spawn sin hooks)")

    script_obj = None
    for name, src in sources:
        try:
            sc = fs.create_script(src)
            _wire_script(sc, sid)
            sc.load()
            sess_dict["buffer"].append("[+] script cargado: %s" % name)
            if script_obj is None:
                script_obj = sc
            else:
                # Permitir varios scripts: guardamos referencia extra para no perderlos
                sess_dict.setdefault("extra_scripts", []).append(sc)
        except Exception as e:
            sess_dict["buffer"].append("[error] cargando %s: %s" % (name, e))

    sess_dict["frida_script"] = script_obj

    # Si es spawn, ahora hacemos resume para que la app corra ya hookeada
    if mode == "spawn":
        try:
            dev.resume(pid)
            sess_dict["buffer"].append("[+] resume -> app corriendo con hooks instalados")
        except Exception as e:
            sess_dict["buffer"].append("[error] resume fallo: %s" % e)
            sess_dict["status"] = "error"

    with _LOCK:
        _SESSIONS[sid] = sess_dict
    return sid, None


def run_inline(pkg, js_source, mode="attach", params=None, serial=None):
    """Corre JS pegado a mano (sin archivo). mode=spawn|attach."""
    if not _HAS_FRIDA:
        return None, "frida no disponible"
    dev, err = _device(serial)
    if err:
        return None, err
    try:
        if mode == "spawn":
            pid = dev.spawn([pkg])
        else:
            pid = dev.get_process(pkg).pid
    except Exception as e:
        return None, "%s fallo: %s" % (mode, e)
    sid = uuid.uuid4().hex[:12]
    sess_dict = {
        "id": sid, "pkg": pkg, "mode": mode, "scripts": ["<inline>"],
        "status": "running", "buffer": [], "device": getattr(dev, "id", None),
        "pid": pid, "frida_session": None, "frida_script": None, "serial": serial,
        "started_at": time.time(),
    }
    with _LOCK:                       # FIX: registrar ANTES de load/resume para no perder console.log
        _SESSIONS[sid] = sess_dict
    try:
        fs = dev.attach(pid)
        sess_dict["frida_session"] = fs
        sc = fs.create_script(js_source)
        _wire_script(sc, sid)
        sc.load()
        sess_dict["frida_script"] = sc
        sess_dict["buffer"].append("[+] script inline cargado")
        if mode == "spawn":
            dev.resume(pid)
            sess_dict["buffer"].append("[+] resume -> app corriendo")
    except Exception as e:
        sess_dict["status"] = "error"
        sess_dict["buffer"].append("[error] " + _short_err(e))
    with _LOCK:
        _SESSIONS[sid] = sess_dict
    return sid, None


def list_sessions():
    with _LOCK:
        return [{"id": s["id"], "pkg": s["pkg"], "mode": s["mode"], "status": s["status"],
                 "scripts": s["scripts"], "started_at": s["started_at"],
                 "lines": len(s["buffer"])} for s in _SESSIONS.values()]


def get_session(sid):
    with _LOCK:
        return _SESSIONS.get(sid)


def drain(sid, since=0):
    """Devuelve las lineas nuevas desde el indice `since`. Devuelve (lines, next_index, status)."""
    with _LOCK:
        s = _SESSIONS.get(sid)
        if not s:
            return [], 0, "missing"
        lines = s["buffer"][since:]
        return lines, len(s["buffer"]), s["status"]


def stop_session(sid):
    with _LOCK:
        s = _SESSIONS.get(sid)
        if not s:
            return False, "sesion no encontrada"
        try:
            sc = s.get("frida_script")
            if sc:
                try: sc.unload()
                except Exception: pass
            for extra in s.get("extra_scripts", []):
                try: extra.unload()
                except Exception: pass
            fs = s.get("frida_session")
            if fs:
                try: fs.detach()
                except Exception: pass
        except Exception as e:
            s["status"] = "error"
            s["buffer"].append("[error] stop: %s" % e)
            return False, str(e)
        s["status"] = "stopped"
        s["buffer"].append("[i] sesion detenida por el usuario")
        return True, None


def server_status(serial=None):
    """True SOLO si hay un proceso frida-server corriendo COMO ROOT en el device
    (unico caso que permite spawn). enumerate_processes() funciona hasta en modo
    'jailed', asi que NO sirve como prueba: usamos 'ps' en el device (verdad real).
    Esto elimina el 'falso verde' que hacia que _ensure_frida_server no lo arrancara."""
    if not _HAS_FRIDA:
        return False, None, "frida no instalado en este Python"
    try:
        import dynadb
        rc, out, _ = dynadb.adb(["shell", "su", "-c",
            "ps -A 2>/dev/null | grep frida-server; ps 2>/dev/null | grep frida-server"], serial)
        out = out or ""
    except Exception as e:
        return False, None, "no pude consultar ps en el device: %s" % e
    # frida-server real (excluir la propia linea del 'grep')
    lines = [l for l in out.splitlines() if "frida-server" in l and "grep" not in l]
    if not lines:
        return False, None, "frida-server NO esta corriendo en el device (hay que arrancarlo)."
    # ¿como root? (USER = primera columna en ps de Android)
    for l in lines:
        p = l.split()
        if p and (p[0] in ("root", "0") or p[0].startswith("0")):
            return True, frida.__version__, None
    return False, frida.__version__, ("frida-server corre pero NO como root -> spawn dara 'jailed'. "
                                      "Rearrancalo como root (su -c '.../frida-server -D').")


def cleanup_sessions(max_age=1800):
    """Elimina sesiones detenidas/error o mas viejas que max_age segundos."""
    now = time.time()
    with _LOCK:
        to_remove = []
        for sid, s in _SESSIONS.items():
            age = now - s.get("started_at", now)
            if s.get("status") in ("stopped", "error", "detached", "missing"):
                to_remove.append(sid)
            elif age > max_age and s.get("status") != "running":
                to_remove.append(sid)
        for sid in to_remove:
            _SESSIONS.pop(sid, None)
        return len(to_remove)