#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AlienProbe - mini toolkit de analisis dinamico de APKs via ADB (didactico).
Cada subcomando corresponde a una tecnica real de pentest movil.
Uso general:
    python dynadb.py [--serial emulator-5554] [--adb C:\\ruta\\adb.exe] <comando> ...
Requiere: 'adb' en el PATH (platform-tools) y un dispositivo/emulador conectado.
Para leer almacenamiento sin root, la app debe ser DEBUGGABLE (build debug).
"""
import argparse, subprocess, sys, os, re, sqlite3, datetime, json, shutil

ADB = "adb"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dynadb_config.json")

# Caracteres no validos en nombres de archivo en Windows (saneado defensivo).
_BAD_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _safe_fs_name(name):
    """Sanea un nombre de archivo para que sea valido en Windows y Linux.
    Quita espacios al borde y caracteres ilegales; si queda vacio, devuelve '_unk'."""
    n = _BAD_FS_CHARS.sub("_", str(name).strip())
    # Nombres reservados en Windows (CON, PRN, AUX, NUL, COM1.., LPT1..)
    base = re.split(r'[._]', n)[0].upper()
    if base in {"CON", "PRN", "AUX", "NUL",
                "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}:
        n = "_" + n
    return n or "_unk"

def load_config():
    try:
        return json.load(open(CONFIG_FILE, encoding="utf-8"))
    except Exception:
        return {}

def save_config(cfg):
    json.dump(cfg, open(CONFIG_FILE, "w", encoding="utf-8"), indent=2)

def resolve_adb(cli_adb):
    """Resuelve la ruta de adb: 1) argumento, 2) config guardada, 3) PATH, 4) preguntar."""
    if cli_adb and cli_adb != "adb":
        return cli_adb
    cfg = load_config()
    p = cfg.get("adb")
    if p and os.path.exists(p):
        return p
    w = shutil.which("adb")
    if w:
        return w
    if sys.stdin.isatty():
        print("[?] No encuentro 'adb' en el PATH.")
        print("    Indica la ruta al ejecutable adb")
        print("    (ej. Windows: C:\\Users\\tu\\platform-tools\\adb.exe | Linux/Mac: /usr/bin/adb)")
        entered = input("adb> ").strip().strip('"')
        if entered and os.path.exists(entered):
            cfg["adb"] = entered
            save_config(cfg)
            print("[+] Ruta guardada en %s" % CONFIG_FILE)
            return entered
        print("[X] Ruta invalida.")
    print("[X] adb no configurado. Ejecuta:  python dynadb.py config --adb <ruta a adb>")
    sys.exit(2)


# Patrones para detectar posibles secretos en archivos extraidos
SECRET_PATTERNS = [
    ("Flag CTF",           re.compile(r"ALIEN\{[^}]{1,80}\}")),
    ("Credencial/Token",   re.compile(r"(?i)(?:password|passwd|pwd|token|secret|api[_-]?key|pin|clave|auth)\s*[=:>\"']{1,3}\s*[^\s<\"']{2,80}")),
    ("JWT",                re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("AWS Access Key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key",     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Firebase URL",       re.compile(r"https?://[a-z0-9.\-]+\.firebaseio\.com")),
    ("Slack Token",        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Private Key",        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Bearer",             re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}")),
    ("Email",              re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("IPv4",               re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("URL",                re.compile(r"https?://[^\s\"'<>]{6,120}")),
    ("Hex secreto (>=32)", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("Base64 largo",       re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")),
]

# ---------------- nucleo adb ----------------
def adb(args, serial=None, binary=False, timeout=120):
    # REPARADO su -c quoting: adb shell re-une los args y pierde las comillas, asi que
    # ["shell","su","-c","chmod 755 x"] llega al device como 'su -c chmod 755 x' (chmod
    # sin args). Lo reescribimos a un solo string: shell "su -c '<cmd>'".
    if len(args) >= 4 and args[0] == "shell" and args[1] == "su" and args[2] == "-c":
        # Escape robusto de comillas simples: cerrar '..'\'' abrir. Evita que un input
        # con comilla rompa el quoting (defensa ante inyeccion en el device).
        _inner = args[3].replace("'", "'\\''")
        args = ["shell", "su -c '%s'" % _inner] + list(args[4:])
    cmd = [ADB] + (["-s", serial] if serial else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        # No abortar el proceso (la GUI podria morir). Devolver error controlado.
        return 127, (b"" if binary else ""), "adb no encontrado (configura la ruta)"
    except subprocess.TimeoutExpired:
        return 124, (b"" if binary else ""), "timeout"
    out = r.stdout if binary else r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    return r.returncode, out, err

def check_device(serial=None):
    rc, out, _ = adb(["devices"], serial)
    lines = [l for l in out.splitlines()[1:] if l.strip() and "device" in l.split("\t")[-1:]]
    devs = [l.split("\t")[0] for l in out.splitlines()[1:] if "\tdevice" in l]
    return devs

def devices_list(serial=None):
    """Lista de (serial, estado) desde 'adb devices -l'."""
    rc, out, _ = adb(["devices", "-l"], serial)
    rows = []
    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        ser = parts[0]
        estado = parts[1] if len(parts) > 1 else "?"
        rows.append({"serial": ser, "state": estado, "raw": line})
    return rows

def connect_host(hostport, serial=None):
    """adb connect host:port (emuladores por red como Nox 127.0.0.1:62001). Devuelve mensaje."""
    rc, out, err = adb(["connect", hostport], serial)
    return (out + err).strip()

# Puertos adb tipicos de emuladores (para auto-conectar)
EMULATOR_PORTS = {
    "Nox": [62001, 62025, 62026],
    "MEmu": [21503],
    "LDPlayer": [5555, 5557],
    "BlueStacks": [5555, 5556, 5557],
    "Otros": [5555],
}

def autoconnect(serial=None):
    """Prueba los puertos adb tipicos de emuladores (Nox, MEmu, LDPlayer...) y conecta."""
    results, seen = [], set()
    for emu, ports in EMULATOR_PORTS.items():
        for port in ports:
            hp = "127.0.0.1:%d" % port
            if hp in seen:
                continue
            seen.add(hp)
            rc, out, err = adb(["connect", hp], serial)
            blob = (out + err).strip()
            low = blob.lower()
            if "connected" in low and "cannot" not in low and "failed" not in low:
                results.append({"emulator": emu, "hostport": hp, "msg": blob})
    return results

def device_profile(serial):
    """Perfil del dispositivo: root?, api level, arch, modelo."""
    prof = {"serial": serial, "root": False, "api": "?", "arch": "?", "model": "?"}
    rc, out, _ = adb(["shell", "getprop", "ro.build.version.sdk"], serial)
    if rc == 0:
        prof["api"] = out.strip()
    rc, out, _ = adb(["shell", "getprop", "ro.product.cpu.abi"], serial)
    if rc == 0:
        prof["arch"] = out.strip()
    rc, out, _ = adb(["shell", "getprop", "ro.product.model"], serial)
    if rc == 0:
        prof["model"] = out.strip()
    rc, who, _ = adb(["shell", "whoami"], serial)
    if rc == 0 and (who or "").strip() == "root":
        prof["root"] = True
    else:
        rc, sout, _ = adb(["shell", "su", "-c", "id"], serial)
        prof["root"] = (rc == 0 and "uid=0" in (sout or ""))
    return prof

def list_packages(serial=None, third_party=True):
    """Lista paquetes. third_party=True -> 'pm list packages -3'."""
    args = ["shell", "pm", "list", "packages"]
    if third_party:
        args.append("-3")
    rc, out, _ = adb(args, serial)
    pkgs = []
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line[len("package:"):])
    return sorted(pkgs)

def install_apk(path, serial=None, replace=True):
    """adb install [-r] <apk>. Devuelve (rc, out+err)."""
    if not os.path.exists(path):
        return 1, "Archivo no encontrado: %s" % path
    args = ["install"]
    if replace:
        args.append("-r")
    args.append(path)
    rc, out, err = adb(args, serial, timeout=300)
    return rc, (out + err).strip()

def resolve_app_label(pkg, serial=None):
    """Intenta resolver el nombre visible de la app via dumpsys (best-effort)."""
    rc, out, _ = adb(["shell", "cmd", "package", "list", "packages", "-f", pkg], serial)
    return pkg

# ---------------- helpers de datos ----------------
def info_data(pkg, serial=None):
    rc, out, _ = adb(["shell", "dumpsys", "package", pkg], serial)
    if rc != 0 or not out.strip() or "Unable to find" in out:
        return None
    d = {}
    m = re.search(r"versionName=(\S+)", out);   d["versionName"] = m.group(1) if m else "?"
    d["debuggable"] = ("DEBUGGABLE" in out)
    m = re.search(r"dataDir=(\S+)", out);        d["dataDir"] = m.group(1) if m else "?"
    m = re.search(r"userId=(\d+)", out);         d["uid"] = m.group(1) if m else "?"
    rc2, _, _ = adb(["shell", "run-as", pkg, "id"], serial)
    d["run_as"] = (rc2 == 0)
    return d

def components_data(pkg, serial=None):
    rc, out, _ = adb(["shell", "dumpsys", "package", pkg], serial)
    comps = sorted(set(re.findall(re.escape(pkg) + r"/[\w.$]+", out)))
    exported, cur = set(), None
    for line in out.splitlines():
        m = re.search(re.escape(pkg) + r"/[\w.$]+", line)
        if m:
            cur = m.group(0)
        if "exported=true" in line and cur:
            exported.add(cur)
    return comps, exported

def dump_sqlite(path, max_rows=100):
    con = sqlite3.connect(path)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in cur.fetchall()]
    lines = []
    for t in tables:
        lines.append("### Tabla: %s" % t)
        try:
            cur.execute('SELECT * FROM "%s" LIMIT %d' % (t, max_rows))
            cols = [c[0] for c in cur.description]
            lines.append(" | ".join(cols))
            for row in cur.fetchall():
                lines.append(" | ".join("" if x is None else str(x) for x in row))
        except Exception as e:
            lines.append("(error leyendo %s: %s)" % (t, e))
        lines.append("")
    con.close()
    return tables, "\n".join(lines)

def scan_text(text):
    found = []
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            found.append((label, m.group(0)))
    return found

# ---------------- almacenamiento (modo root/runas/none) ----------------
def storage_data(pkg, serial=None, outdir="loot", mode="auto"):
    """
    Version estructurada de cmd_storage para la GUI. Usa core.access si esta disponible
    para soportar root/runas/none; si no, cae al comportamiento run-as heredado.

    Devuelve dict: {mode, prefs:[{name,content,secrets}], dbs:[{name,tables,rows,secrets}],
                    files:[...], findings:[], loot_dir, error}
    """
    res = {"mode": "none", "prefs": [], "dbs": [], "files": [], "findings": [], "loot_dir": "", "error": None}
    try:
        from core import access
        m = access.get_access_mode(pkg, serial, prefer=mode)
    except Exception:
        access = None
        m = "runas" if _legacy_runas_ok(pkg, serial) else "none"
    res["mode"] = m
    lootdir = os.path.join(outdir, pkg)
    os.makedirs(lootdir, exist_ok=True)
    res["loot_dir"] = lootdir
    if m == "none":
        res["error"] = ("Sin acceso: ni root ni run-as (app no debuggable). "
                        "Usa un emulador rooteado o repackaging (patch).")
        return res

    # SharedPreferences
    if access:
        rc, prefs, _ = access.list_app_dir(pkg, "shared_prefs", serial, mode=m)
    else:
        rc, out, _ = adb(["exec-out", "run-as", pkg, "ls", "shared_prefs"], serial)
        prefs = [x for x in out.split() if x.endswith(".xml")] if rc == 0 else []
    for f in prefs:
        if access:
            rc, data, err = access.read_app_file(pkg, "shared_prefs/%s" % f, serial, mode=m)
            content = data.decode("utf-8", "replace") if rc == 0 else ""
        else:
            rc, content, _ = adb(["exec-out", "run-as", pkg, "cat", "shared_prefs/%s" % f], serial)
        if rc == 0:
            safe = _safe_fs_name(f)
            open(os.path.join(lootdir, safe), "w", encoding="utf-8").write(content)
            secs = [{"label": l, "value": v} for l, v in scan_text(content)]
            res["prefs"].append({"name": f, "content": content, "secrets": secs})
            for l, v in scan_text(content):
                res["findings"].append(("shared_prefs/%s" % f, l, v))

    # SQLite (trae tambien -wal/-shm: las apps en modo WAL guardan los datos recientes
    # en el .db-wal; copiar solo el .db da tablas vacias o 'database disk image is malformed').
    def _read_db_file(rel):
        if access:
            rc, data, _ = access.read_app_file(pkg, "databases/%s" % rel, serial, mode=m)
            return rc, data
        rc, data, _ = adb(["exec-out", "run-as", pkg, "cat", "databases/%s" % rel], serial, binary=True)
        return rc, data

    if access:
        rc, dbfiles, _ = access.list_app_dir(pkg, "databases", serial, mode=m)
    else:
        rc, out, _ = adb(["exec-out", "run-as", pkg, "ls", "databases"], serial)
        dbfiles = out.split() if rc == 0 else []
    def _clean_sidecars(p):
        for suf in ("-wal", "-shm", "-journal"):
            try:
                if os.path.exists(p + suf):
                    os.remove(p + suf)
            except OSError:
                pass

    def _copy_and_dump(db, p):
        """Copia el .db + sidecars (-wal/-journal) y lo vuelca. En modo root usa
        'cp a /data/local/tmp + adb pull' (transferencia binaria fiable); en run-as
        usa 'exec-out cat'. NO copia el -shm (SQLite lo recrea). Devuelve (tables, dump) o lanza."""
        _clean_sidecars(p)
        if m == "root":
            dbdir = "/data/data/%s/databases" % pkg
            tmp = "/data/local/tmp"
            adb(["shell", "su", "-c",
                 "rm -f %s/_dyn.db %s/_dyn.db-wal %s/_dyn.db-journal; "
                 "cp -f %s/%s %s/_dyn.db 2>/dev/null; "
                 "cp -f %s/%s-wal %s/_dyn.db-wal 2>/dev/null; "
                 "cp -f %s/%s-journal %s/_dyn.db-journal 2>/dev/null; "
                 "chmod 644 %s/_dyn.db* 2>/dev/null; true"
                 % (tmp, tmp, tmp, dbdir, db, tmp, dbdir, db, tmp, dbdir, db, tmp, tmp)], serial)
            adb(["pull", "%s/_dyn.db" % tmp, p], serial)
            for suf in ("-wal", "-journal"):
                adb(["pull", "%s/_dyn.db%s" % (tmp, suf), p + suf], serial)  # falla silencioso si no existe
            adb(["shell", "su", "-c", "rm -f %s/_dyn.db*" % tmp], serial)
        else:
            rc, data = _read_db_file(db)
            if rc != 0 or data[:15] != b"SQLite format 3":
                raise RuntimeError("no se pudo leer %s (rc=%s)" % (db, rc))
            open(p, "wb").write(data)
            for suf in ("-wal", "-journal"):
                try:
                    rcs, sdata = _read_db_file(db + suf)
                    if rcs == 0 and sdata:
                        open(p + suf, "wb").write(sdata)
                except OSError:
                    pass
        # Verificar que la copia es una SQLite válida
        try:
            with open(p, "rb") as f:
                head = f.read(15)
        except OSError:
            head = b""
        if head != b"SQLite format 3":
            raise RuntimeError("la copia de %s no es una base SQLite válida" % db)
        return dump_sqlite(p)

    dbs = [x.strip() for x in dbfiles
           if x.strip() and not x.strip().endswith(("-journal", "-wal", "-shm"))]
    for db in dbs:
        p = os.path.join(lootdir, _safe_fs_name(db))
        note = None
        try:
            tables, dump = _copy_and_dump(db, p)
        except Exception:
            # La copia en vivo salio inconsistente (app escribiendo / WAL sin checkpoint).
            # Cerramos la app y recopiamos: sin escritor, el snapshot es consistente.
            try:
                adb(["shell", "am", "force-stop", pkg], serial)
                import time as _t
                _t.sleep(1.2)
                tables, dump = _copy_and_dump(db, p)
                note = "recuperada tras cerrar la app (am force-stop)"
            except Exception as e2:
                res["dbs"].append({"name": db, "tables": [], "dump": "", "secrets": [],
                                   "error": "%s (base bloqueada/corrupta incluso tras force-stop)" % e2})
                continue
        open(p + ".dump.txt", "w", encoding="utf-8").write(dump)
        secs = [{"label": l, "value": v} for l, v in scan_text(dump)]
        entry = {"name": db, "tables": tables, "dump": dump, "secrets": secs}
        if note:
            entry["note"] = note
        res["dbs"].append(entry)
        for l, v in scan_text(dump):
            res["findings"].append(("databases/%s" % db, l, v))
    return res

def _legacy_runas_ok(pkg, serial=None):
    rc, _, _ = adb(["shell", "run-as", pkg, "id"], serial)
    return rc == 0

# ---------------- comandos ----------------
def cmd_devices(a):
    rc, out, _ = adb(["devices", "-l"], a.serial)
    print(out.strip() or "(sin dispositivos)")

def cmd_packages(a):
    pkgs = list_packages(a.serial, third_party=not a.all)
    if a.filter:
        pkgs = [p for p in pkgs if a.filter.lower() in p.lower()]
    print("\n".join(pkgs) or "(sin paquetes)")

def cmd_connect(a):
    if getattr(a, "auto", False) or not a.hostport:
        res = autoconnect(a.serial)
        if not res:
            print("[X] Ningun puerto tipico de emulador respondio (Nox 62001/62025, MEmu 21503, LDPlayer 5555...).")
        for r in res:
            print("[+] %s -> %s (%s)" % (r["emulator"], r["hostport"], r["msg"]))
        return
    print(connect_host(a.hostport, a.serial))

def cmd_install(a):
    rc, msg = install_apk(a.apk, a.serial, replace=not a.no_replace)
    print("[%s] %s" % ("OK" if rc == 0 else "X", msg))

def cmd_profile(a):
    p = device_profile(a.serial)
    print("serial: %s" % p["serial"])
    print("model : %s" % p["model"])
    print("api   : %s" % p["api"])
    print("arch  : %s" % p["arch"])
    print("root  : %s" % ("SI" if p["root"] else "NO"))

def cmd_info(a):
    d = info_data(a.package, a.serial)
    if not d:
        print("[X] Paquete %s no encontrado (¿instalado?)." % a.package); return
    print("Paquete    : %s" % a.package)
    print("versionName: %s" % d["versionName"])
    print("debuggable : %s  (run-as %s)" % ("SI" if d["debuggable"] else "NO",
                                             "disponible" if d["run_as"] else "NO disponible"))
    print("dataDir    : %s" % d["dataDir"])
    print("uid        : %s" % d["uid"])
    if not d["run_as"]:
        print("[i] Sin run-as no puedo leer su almacenamiento sin root (la app no es debug).")

def cmd_components(a):
    comps, exported = components_data(a.package, a.serial)
    print("Componentes declarados (%d):" % len(comps))
    for c in comps:
        print("  %s%s" % ("[EXPORTED] " if c in exported else "", c))
    if exported:
        print("\n[!] Exportados = accesibles desde otras apps -> MASVS-PLATFORM (CWE-926):")
        for c in sorted(exported):
            print("  %s" % c)

def cmd_storage(a):
    pkg, serial = a.package, a.serial
    res = storage_data(pkg, serial, outdir=a.out, mode=getattr(a, "mode", "auto"))
    m = res["mode"]
    if m == "none":
        print("[X] %s" % res.get("error", "Sin acceso"))
        return []
    print("[+] Modo de acceso: %s" % m)
    for p in res["prefs"]:
        print("[+] prefs  : shared_prefs/%s" % p["name"])
    for db in res["dbs"]:
        if db.get("error"):
            print("[!] sqlite : databases/%s (error: %s)" % (db["name"], db["error"]))
        else:
            print("[+] sqlite : databases/%s  (tablas: %s)" % (db["name"], ", ".join(db["tables"])))
    print("\n=== Posibles secretos ===")
    if not res["findings"]:
        print("(ninguno con los patrones actuales)")
    for src, label, val in res["findings"]:
        print("  [%s] %s -> %s" % (label, src, val))
    print("\n[i] Modo: %s | Botin guardado en: %s" % (m, res["loot_dir"]))
    return res["findings"]

def cmd_launch(a):
    comp = "%s/%s" % (a.package, a.activity)
    args = ["shell", "am", "start", "-n", comp]
    for k, v in (a.ei or []):
        args += ["--ei", k, v]
    for k, v in (a.es or []):
        args += ["--es", k, v]
    rc, out, err = adb(args, a.serial)
    print((out + err).strip())
    blob = out + err
    if "Permission Denial" in blob:
        print("[i] Permission Denial -> el activity NO es exportado.")
    elif rc == 0 and "Starting" in blob:
        print("[+] Lanzado %s. Si abrio sin login -> activity exportada / IDOR (MASVS-PLATFORM/AUTH)." % comp)

def cmd_screenshot(a):
    rc, data, err = adb(["exec-out", "screencap", "-p"], a.serial, binary=True)
    if rc == 0 and data[:8] == b"\x89PNG\r\n\x1a\n":
        open(a.out, "wb").write(data)
        print("[+] Captura -> %s" % a.out)
    else:
        print("[X] No pude capturar la pantalla: %s" % (err or "formato inesperado"))

def cmd_logcat(a):
    rc, pid, _ = adb(["shell", "pidof", "-s", a.package], a.serial)
    pid = pid.strip()
    if pid:
        rc, out, _ = adb(["logcat", "-d", "--pid", pid, "-t", str(a.lines)], a.serial)
    else:
        rc, out, _ = adb(["logcat", "-d", "-t", "3000"], a.serial)
        key = a.tag or a.package.split(".")[-1]
        out = "\n".join(l for l in out.splitlines() if key.lower() in l.lower())
    print(out.strip() or "(sin logs)")

def cmd_scan(a):
    total = 0
    for root, _, files in os.walk(a.path):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                txt = open(fp, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for label, val in scan_text(txt):
                print("  [%s] %s -> %s" % (label, fp, val)); total += 1
    print("\n[i] %d coincidencias." % total)

def cmd_report(a):
    pkg = a.package
    outdir = os.path.join(a.out, pkg)
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    info = info_data(pkg, a.serial)
    comps, exported = components_data(pkg, a.serial)
    shot = os.path.join(outdir, "pantalla.png")
    rc, data, _ = adb(["exec-out", "screencap", "-p"], a.serial, binary=True)
    if rc == 0 and data[:8] == b"\x89PNG\r\n\x1a\n":
        open(shot, "wb").write(data)
    findings = cmd_storage(argparse.Namespace(package=pkg, serial=a.serial, out=a.out))
    md = []
    md.append("# Informe dinámico (AlienProbe) — %s" % pkg)
    md.append("Fecha: %s\n" % ts)
    if info:
        md.append("## Recon")
        md.append("- versionName: %s" % info["versionName"])
        md.append("- debuggable: %s (run-as %s)" % ("SÍ" if info["debuggable"] else "NO",
                  "disponible" if info["run_as"] else "no"))
        if info["debuggable"]:
            md.append("  - Hallazgo: **app debuggable** → MASVS-RESILIENCE (CWE-489).")
        md.append("")
    md.append("## Componentes exportados")
    if exported:
        for c in sorted(exported):
            md.append("- `%s` → **exportado sin protección** (MASVS-PLATFORM, CWE-926)" % c)
    else:
        md.append("- (ninguno detectado)")
    md.append("\n## Almacenamiento / secretos")
    if findings:
        for src, label, val in findings:
            md.append("- [%s] `%s` → `%s` (MASVS-STORAGE, CWE-312)" % (label, src, val))
    else:
        md.append("- (sin hallazgos)")
    md.append("\n## Evidencia")
    md.append("- Captura: `%s`" % shot)
    md.append("- Botín (prefs/DB): `%s`" % outdir)
    md.append("\n## Cobertura OWASP MASVS (resumen)")
    checks = [
        ("MASVS-STORAGE (datos en claro)",       bool(findings)),
        ("MASVS-PLATFORM (activity exportada)",  bool(exported)),
        ("MASVS-RESILIENCE (app debuggable)",    bool(info and info.get("debuggable"))),
    ]
    for name, hit in checks:
        md.append("- [%s] %s" % ("HALLAZGO" if hit else "ok", name))
    path = os.path.join(outdir, "informe.md")
    open(path, "w", encoding="utf-8").write("\n".join(md))
    print("\n[+] Informe generado -> %s" % path)

def cmd_selftest(a):
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.db")
    con = sqlite3.connect(p); c = con.cursor()
    c.execute("CREATE TABLE secrets(key TEXT, value TEXT)")
    c.execute("INSERT INTO secrets VALUES('db_flag','ALIEN{sqlit3_pl41nt3xt}')")
    con.commit(); con.close()
    tables, dump = dump_sqlite(p)
    found = scan_text(dump)
    ok = ("secrets" in tables) and any("ALIEN{" in v for _, v in found)
    print("selftest sqlite+scan:", "OK" if ok else "FALLO")
    print("  tablas:", tables)
    print("  secretos:", found)
    sys.exit(0 if ok else 1)

def cmd_preset(a):
    """Ejecuta un preset del catalogo presets.json por CLI. Requiere frida en el venv."""
    import json as _json
    presets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "presets.json")
    try:
        catalog = _json.load(open(presets_path, encoding="utf-8")).get("presets", [])
    except Exception as e:
        print("[X] No pude leer presets.json: %s" % e); sys.exit(2)
    if a.list_presets:
        for p in catalog:
            print("  %-18s  [%s]  %s" % (p["id"], p.get("type","?"), p["title"]))
        return
    preset = next((p for p in catalog if p.get("id") == a.preset_id), None)
    if not preset:
        print("[X] Preset no encontrado: %s  (usa --list)" % a.preset_id); sys.exit(2)
    pkg = a.package
    if not pkg:
        print("[X] Indica el paquete: dynadb preset <id> <paquete>"); sys.exit(2)
    # params simples k=v
    params = {}
    for kv in (a.params or []):
        if "=" in kv:
            k, v = kv.split("=", 1); params[k.strip()] = v.strip()
    from core import instrument
    if not instrument.has_frida():
        print("[X] frida no instalado en este Python. Usa el venv (.venv/bin/python)."); sys.exit(3)
    ptype = preset.get("type", "attach")
    scripts = preset.get("scripts", [])
    inline_js = preset.get("inline_js")
    sources = list(scripts)
    if inline_js:
        sources.append(("<inline>", instrument._apply_params(inline_js, params)))
    if ptype == "spawn":
        sid, err = instrument.spawn_with_scripts(pkg, sources, params=params, serial=a.serial)
    elif ptype == "attach":
        sid, err = instrument.attach_with_scripts(pkg, sources, params=params, serial=a.serial)
    else:
        print("[X] Tipo '%s' no soportado por CLI (usa la GUI para core/custom)." % ptype); sys.exit(2)
    if err:
        print("[X] %s" % err); sys.exit(1)
    print("[+] Sesion: %s (%s)" % (sid, ptype))
    print("[i] salidas en vivo (Ctrl+C para detener):")
    try:
        idx = 0
        while True:
            import time; time.sleep(0.5)
            lines, idx, status = instrument.drain(sid, idx)
            for ln in lines:
                print("  " + ln)
            if status in ("stopped", "detached", "error", "missing"):
                print("[i] sesion %s" % status); break
    except KeyboardInterrupt:
        instrument.stop_session(sid)
        print("\n[i] detenido.")


def cmd_config(a):
    cfg = load_config()
    if a.adb:
        cfg["adb"] = a.adb; print("[+] adb = %s (guardado)" % a.adb)
    if a.serial:
        cfg["serial"] = a.serial; print("[+] serial por defecto = %s (guardado)" % a.serial)
    save_config(cfg)
    print("Config (%s): %s" % (CONFIG_FILE, cfg))

def cmd_doctor(a):
    print("== AlienProbe doctor — verificacion del entorno ==")
    print("adb            : %s" % ADB)
    rc, out, _ = adb(["version"])
    print("adb responde   : %s" % (out.splitlines()[0].strip() if rc == 0 and out else "NO"))
    rc, out, _ = adb(["devices"])
    devs = [l.split("\t")[0] for l in out.splitlines()[1:] if "\tdevice" in l]
    print("dispositivos   : %s" % (", ".join(devs) if devs else "NINGUNO (conecta emulador o telefono con depuracion USB)"))
    ser = a.serial or (devs[0] if devs else None)
    if ser:
        rc, who, _ = adb(["shell", "whoami"], ser); who = who.strip()
        rc2, sout, _ = adb(["shell", "su", "-c", "id"], ser)
        rooted = (who == "root") or ("uid=0" in (sout or ""))
        print("shell user     : %s  -> %s" % (who or "?", "ROOT disponible" if rooted else "SIN root"))
        if not rooted:
            print("                 (en emulador Google APIs: 'adb root' te da root)")
    print("")
    print("Para analisis dinamico necesitas CORRIENDO:")
    print("  1) adb en el host + 1 dispositivo listado en 'adb devices'")
    print("  2) el emulador/telefono encendido con la app instalada")
    print("  3) app DEBUG -> run-as (sin root) | app RELEASE -> root en device o repackaging")
    print("  4) trafico   -> proxy (mitmproxy/Burp) + CA instalada en el device")
    print("  5) hooking   -> frida-server (root) o frida-gadget (repackaged)")

# ---------------- CLI ----------------
def build_parser():
    p = argparse.ArgumentParser(description="AlienProbe - analisis dinamico de APKs via adb")
    p.add_argument("--serial", help="serial del dispositivo (adb -s), ej. emulator-5554")
    p.add_argument("--adb", default="adb", help="ruta al ejecutable adb")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("devices")
    x = sub.add_parser("packages"); x.add_argument("--filter"); x.add_argument("--all", action="store_true")
    x = sub.add_parser("connect");   x.add_argument("hostport", nargs="?", help="host:port (ej. 127.0.0.1:62001)"); x.add_argument("--auto", action="store_true", help="probar puertos tipicos de emuladores")
    x = sub.add_parser("install");   x.add_argument("apk"); x.add_argument("--no-replace", action="store_true")
    x = sub.add_parser("profile")
    x = sub.add_parser("info");        x.add_argument("package")
    x = sub.add_parser("components");  x.add_argument("package")
    x = sub.add_parser("storage");     x.add_argument("package"); x.add_argument("--out", default="loot"); x.add_argument("--mode", choices=["auto","root","runas"], default="auto")
    x = sub.add_parser("launch");      x.add_argument("package"); x.add_argument("activity")
    x.add_argument("--ei", nargs=2, action="append", metavar=("KEY", "VAL"))
    x.add_argument("--es", nargs=2, action="append", metavar=("KEY", "VAL"))
    x = sub.add_parser("screenshot");  x.add_argument("--out", default="pantalla.png")
    x = sub.add_parser("logcat");      x.add_argument("package"); x.add_argument("--tag"); x.add_argument("--lines", type=int, default=200)
    x = sub.add_parser("scan");        x.add_argument("path")
    x = sub.add_parser("report");      x.add_argument("package"); x.add_argument("--out", default="loot")
    x = sub.add_parser("audit");       x.add_argument("package"); x.add_argument("--out", default="loot")
    x = sub.add_parser("preset")
    x.add_argument("preset_id", nargs="?", help="id del preset (ver --list)")
    x.add_argument("package", nargs="?", help="paquete target")
    x.add_argument("--list", dest="list_presets", action="store_true", help="listar presets disponibles")
    x.add_argument("--param", dest="params", action="append", metavar="KEY=VAL", help="parametro del preset")
    x = sub.add_parser("config"); x.add_argument("--adb"); x.add_argument("--serial")
    x = sub.add_parser("doctor")
    sub.add_parser("selftest")
    return p

def main():
    global ADB
    p = build_parser()
    a = p.parse_args()
    # 'config', 'selftest' y 'scan' no requieren adb resuelto
    if a.cmd == "config":
        cmd_config(a); return
    if a.cmd == "selftest":
        cmd_selftest(a); return
    if a.cmd == "scan":
        cmd_scan(a); return
    if a.cmd == "preset" and getattr(a, "list_presets", False):
        cmd_preset(a); return
    ADB = resolve_adb(a.adb)   # pregunta la ruta de adb si hace falta
    fn = {
        "devices": cmd_devices, "info": cmd_info, "components": cmd_components,
        "storage": cmd_storage, "launch": cmd_launch, "screenshot": cmd_screenshot,
        "logcat": cmd_logcat, "report": cmd_report, "doctor": cmd_doctor,
        "packages": cmd_packages, "connect": cmd_connect, "install": cmd_install,
        "profile": cmd_profile, "audit": cmd_report, "preset": cmd_preset,
    }[a.cmd]
    fn(a)

if __name__ == "__main__":
    main()
