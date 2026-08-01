#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run.py - Bootstrap de AlienProbe.
- Crea un entorno virtual (.venv) si no existe.
- Instala las dependencias de requirements.txt (solo si cambiaron).
- Ejecuta el sistema (GUI si existe gui.py/app.py; si no, el CLI dynadb.py).
- Registra todo en logs/.

Uso:
    python run.py                 # arranca (GUI o 'doctor' por defecto)
    python run.py doctor
    python run.py storage com.taller.bancoalien
    python run.py selftest
"""
import os, sys, subprocess, venv, hashlib, logging, datetime, json, shutil, platform, stat, urllib.request, zipfile

BASE   = os.path.dirname(os.path.abspath(__file__))
VENV   = os.path.join(BASE, ".venv")
REQ    = os.path.join(BASE, "requirements.txt")
LOGDIR = os.path.join(BASE, "logs")

def venv_python():
    return os.path.join(VENV, "Scripts", "python.exe") if os.name == "nt" \
        else os.path.join(VENV, "bin", "python")

PLATFORM_TOOLS = {
    "Windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    "Linux":   "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    "Darwin":  "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
}
CONFIG = os.path.join(BASE, "dynadb_config.json")

def _load_cfg():
    try: return json.load(open(CONFIG, encoding="utf-8"))
    except Exception: return {}

def _save_cfg(cfg):
    json.dump(cfg, open(CONFIG, "w", encoding="utf-8"), indent=2)

def ensure_adb():
    """Garantiza adb: config > PATH > platform-tools local > descarga oficial de Google."""
    adbname = "adb.exe" if os.name == "nt" else "adb"
    cfg = _load_cfg()
    p = cfg.get("adb")
    if p and os.path.exists(p):
        logging.info("adb (config): %s", p); return p
    w = shutil.which("adb")
    if w:
        cfg["adb"] = w; _save_cfg(cfg); logging.info("adb (PATH): %s", w); return w
    local = os.path.join(BASE, "platform-tools", adbname)
    if os.path.exists(local):
        cfg["adb"] = local; _save_cfg(cfg); logging.info("adb (local): %s", local); return local
    url = PLATFORM_TOOLS.get(platform.system())
    if not url:
        logging.warning("SO no reconocido; instala adb manualmente."); return None
    logging.info("adb no encontrado -> descargando platform-tools oficial: %s", url)
    zpath = os.path.join(BASE, "platform-tools.zip")
    try:
        urllib.request.urlretrieve(url, zpath)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(BASE)
        os.remove(zpath)
        if os.name != "nt" and os.path.exists(local):
            os.chmod(local, os.stat(local).st_mode | stat.S_IEXEC)
        cfg["adb"] = local; _save_cfg(cfg)
        logging.info("platform-tools instalado -> adb: %s", local)
        return local
    except Exception as e:
        logging.warning("No pude descargar platform-tools (%s). Bajalo manual: %s", e, url)
        return None

def setup_logging():
    os.makedirs(LOGDIR, exist_ok=True)
    logfile = os.path.join(LOGDIR, "dynadb_%s.log" % datetime.datetime.now().strftime("%Y%m%d"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(logfile, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
    )
    logging.info("=== AlienProbe (0xAlienSec) / run.py ===  (log: %s)", logfile)

# Versiones de Python con wheels de frida disponibles (evita 3.14+)
COMPAT = ("3.12", "3.11")   # versiones con wheels de frida (3.13/3.14 NO)
PY_DOWNLOAD = "https://www.python.org/downloads/  (elige Python 3.12.x)"

def _py_ver(cmd):
    try:
        out = subprocess.check_output(
            cmd + ["-c", "import sys;print('%d.%d'%sys.version_info[:2])"],
            text=True, stderr=subprocess.DEVNULL).strip()
        return out
    except Exception:
        return None

def find_python():
    """Devuelve (cmd_lista, version) de un Python compatible con frida, o (None, None)."""
    cur = "%d.%d" % (sys.version_info[0], sys.version_info[1])
    if cur in COMPAT:
        return [sys.executable], cur
    cands = []
    if os.name == "nt":
        for v in COMPAT:
            cands.append(["py", "-" + v])          # lanzador oficial
        la = os.environ.get("LOCALAPPDATA", "")
        for v in COMPAT:
            n = v.replace(".", "")
            cands.append([os.path.join(la, "Programs", "Python", "Python" + n, "python.exe")])
            cands.append([os.path.join("C:\\", "Python" + n, "python.exe")])
    else:
        for v in COMPAT:
            cands.append(["python" + v])
            cands.append([os.path.join("/usr/bin", "python" + v)])
            cands.append([os.path.join("/usr/local/bin", "python" + v)])
    for c in cands:
        if len(c) == 1 and (os.sep in c[0]) and not os.path.exists(c[0]):
            continue
        v = _py_ver(c)
        if v in COMPAT:
            return c, v
    return None, None

def _venv_valid():
    """True si el .venv sirve en ESTA maquina. Un venv copiado de otro equipo tiene el
    python.exe pero su pyvenv.cfg apunta a un Python inexistente -> pip falla ('No pyvenv.cfg
    file', rc 106). Por eso validamos ejecutando el python del venv, no solo que exista."""
    py = venv_python()
    if not os.path.exists(py):
        return False
    if not os.path.exists(os.path.join(VENV, "pyvenv.cfg")):
        return False
    try:
        r = subprocess.run([py, "-c", "import sys"], capture_output=True, timeout=25)
        return r.returncode == 0
    except Exception:
        return False


def _create_venv():
    pycmd, ver = find_python()
    if pycmd:
        logging.info("Creando venv con Python %s  (%s) ...", ver, " ".join(pycmd))
        subprocess.check_call(pycmd + ["-m", "venv", VENV])
        logging.info("Entorno virtual creado con Python %s.", ver)
    else:
        cur = "%d.%d" % (sys.version_info[0], sys.version_info[1])
        logging.warning("=" * 70)
        logging.warning("No encontre Python 3.11/3.12/3.13 (los que soportan frida).")
        logging.warning("Tu Python actual es %s: sirve para la GUI, pero NO para frida.", cur)
        logging.warning("Instala Python 3.12 desde: %s", PY_DOWNLOAD)
        logging.warning("=" * 70)
        venv.create(VENV, with_pip=True)
        logging.info("Entorno virtual creado con el Python actual (sin frida).")


def ensure_venv():
    if _venv_valid():
        logging.info("Entorno virtual OK.")
        return
    if os.path.isdir(VENV):
        logging.warning("El .venv no es valido en esta maquina (copiado de otro equipo o roto). "
                        "Recreando desde cero ...")
        try:
            shutil.rmtree(VENV)
        except Exception as e:
            logging.error("No pude borrar el .venv roto (%s). Borralo a mano y reintenta:  "
                          "rmdir /s /q .venv", e)
            raise
    _create_venv()

def req_hash():
    return hashlib.sha256(open(REQ, "rb").read()).hexdigest() if os.path.exists(REQ) else ""

def _pip(*args):
    subprocess.check_call([venv_python(), "-m", "pip"] + list(args))

def ensure_deps():
    if os.path.exists(REQ):
        marker = os.path.join(VENV, ".installed")
        current = req_hash()
        prev = open(marker, encoding="utf-8").read().strip() if os.path.exists(marker) else ""
        if current != prev:
            logging.info("Instalando dependencias base (Flask, rich) ...")
            try:
                _pip("install", "--upgrade", "pip")
                _pip("install", "-r", REQ)
                open(marker, "w", encoding="utf-8").write(current)
                logging.info("Dependencias base instaladas.")
            except Exception as e:
                logging.warning("Fallo instalando dependencias base (%s).", e)
        else:
            logging.info("Dependencias base al dia.")
    ensure_frida_pkg()


def ensure_frida_pkg():
    """Fija frida a la serie 16.x. CLAVE: Frida 17 ELIMINO el puente 'Java' incorporado,
    asi que los scripts crudos (create_script) que usan Java.perform/Java.use NO funcionan
    en 17 (el bypass de root/pinning falla con \"'Java' no disponible\"). La 16.x trae el
    puente Java de fabrica y es la version estandar de los tutoriales de Frida.
    Best-effort: no bloquea la GUI (el analisis estatico funciona igual)."""
    try:
        ver = subprocess.check_output(
            [venv_python(), "-c", "import frida;print(frida.__version__)"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        ver = ""
    try:
        major = int(ver.split(".")[0])
    except Exception:
        major = 0
    if ver and 0 < major < 17:
        logging.info("frida %s OK (puente Java incorporado).", ver)
        return
    logging.info("frida %s NO sirve para scripts crudos (17 quito el puente Java). "
                 "Fijando frida 16.x + frida-tools 13.x ...", ver or "ausente")
    try:
        _pip("install", "--force-reinstall", "frida>=16.4,<17", "frida-tools>=13,<14")
        newver = subprocess.check_output(
            [venv_python(), "-c", "import frida;print(frida.__version__)"],
            text=True, stderr=subprocess.DEVNULL).strip()
        logging.info("frida fijado a %s.  IMPORTANTE: re-sube frida-server con la MISMA version: "
                     "  .venv\\Scripts\\python setup_frida.py", newver)
    except Exception as e:
        logging.warning("No pude fijar frida 16.x (%s). Con frida 17 el bypass Java fallara; "
                        "instala a mano:  .venv\\Scripts\\pip install \"frida>=16.4,<17\" \"frida-tools>=13,<14\"", e)

def run_app(args):
    for entry in ("gui.py", "app.py"):
        p = os.path.join(BASE, entry)
        if os.path.exists(p):
            logging.info("Ejecutando interfaz: %s", entry)
            return subprocess.call([venv_python(), p] + args)
    logging.info("Aun no hay GUI; ejecuto el CLI dynadb.py")
    return subprocess.call([venv_python(), os.path.join(BASE, "dynadb.py")] + (args or ["doctor"]))

def _sync(source):
    """Copia el codigo desde 'source' a esta carpeta, conservando .venv, platform-tools,
    dynadb_config.json, logs y loot. Asi 'python run.py' siempre corre lo ultimo."""
    if not source or not os.path.isdir(source):
        logging.warning("sync: el origen guardado no existe en ESTE equipo: %s", source)
        logging.warning("sync: parece una copia a otra PC -> se ignora el origen y se ejecuta LOCAL desde %s", BASE)
        return
    if os.path.abspath(source) == os.path.abspath(BASE):
        logging.info("Corriendo desde el propio origen (%s); no hay nada que copiar.", BASE)
        return
    logging.info("Sincronizando codigo:  origen=%s  ->  destino=%s", source, BASE)
    if os.name == "nt":
        subprocess.call(["robocopy", source, BASE, "/E",
                         "/XD", ".venv", "platform-tools", "__pycache__", "logs", "loot", ".git",
                         "/XF", "dynadb_config.json"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        import shutil
        skip_d = {".venv", "platform-tools", "__pycache__", "logs", "loot", ".git"}
        skip_f = {"dynadb_config.json"}
        for root, dirs, files in os.walk(source):
            dirs[:] = [d for d in dirs if d not in skip_d]
            rel = os.path.relpath(root, source)
            dst = BASE if rel == "." else os.path.join(BASE, rel)
            os.makedirs(dst, exist_ok=True)
            for fn2 in files:
                if fn2 in skip_f: continue
                try: shutil.copy2(os.path.join(root, fn2), os.path.join(dst, fn2))
                except Exception as e: logging.warning("sync %s: %s", fn2, e)
    logging.info("Codigo sincronizado en %s.", BASE)

def main():
    setup_logging()
    try:
        drive = os.path.splitdrive(BASE)[0] or "/"
        logging.info("AlienProbe arrancando  |  carpeta=%s  |  disco=%s  |  host=%s  |  SO=%s  |  py=%s",
                     BASE, drive, platform.node(), platform.system(), platform.python_version())
        _cfg0 = _load_cfg()
        _venv_ok = os.path.isdir(VENV)
        _pt_ok   = os.path.isdir(os.path.join(BASE, "platform-tools"))
        _src0    = _cfg0.get("sync_source")
        _src_ok  = bool(_src0) and os.path.isdir(_src0)
        if not _venv_ok and not _pt_ok:
            logging.info("Equipo NUEVO detectado (sin .venv ni platform-tools): se preparara todo desde cero.")
        logging.info("Escaneo entorno  |  .venv=%s  |  platform-tools=%s  |  sync_source=%s",
                     "si" if _venv_ok else "no",
                     "si" if _pt_ok else "no (se descargara)",
                     (_src0 + (" [valido]" if _src_ok else " [NO existe aqui -> se ignora]")) if _src0 else "no configurado")
        # --sync <origen>: guarda el origen y sincroniza el codigo antes de arrancar.
        # Una vez configurado, cada 'python run.py' sincroniza solo.
        app_args = sys.argv[1:]
        cfg = _load_cfg()
        src = None
        if "--sync" in app_args:
            i = app_args.index("--sync")
            src = app_args[i + 1] if i + 1 < len(app_args) else None
            del app_args[i:i + (2 if src else 1)]
            if src:
                cfg["sync_source"] = src; _save_cfg(cfg)
        src = src or cfg.get("sync_source")
        if src:
            _sync(src)
        ensure_adb()
        ensure_venv()
        ensure_deps()
        rc = run_app(app_args)
        logging.info("Proceso finalizado (rc=%s).", rc)
        sys.exit(rc)
    except KeyboardInterrupt:
        logging.info("Interrumpido por el usuario.")
        sys.exit(130)

if __name__ == "__main__":
    main()
