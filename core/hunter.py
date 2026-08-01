# -*- coding: utf-8 -*-
"""
hunter.py  -  Modulo adicional "Cazador de secretos" (estatico) para AlienProbe.

Aislado: NO modifica ni depende de la logica existente. Ofrece:
  - Resolver el APK (ruta dada por el usuario, cache en loot/, o pull del dispositivo).
  - (Opcional) instalar jadx solo y decompilar a fuente Java para buscar con contexto.
  - Buscar patrones (passwords, secretos, tokens, URLs) y las flags ALIEN{...}.

Si jadx/Java no estan disponibles, cae con gracia a un barrido de cadenas del binario
(dex/recursos/assets), asi el modulo SIEMPRE funciona. Nada de esto afecta al resto.
"""
import os
import re
import io
import zipfile
import hashlib
import shutil
import subprocess
import urllib.request
import platform

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # carpeta AlienProbe/
TOOLS = os.path.join(BASE, "tools")
JADX_DIR = os.path.join(TOOLS, "jadx")
JADX_CACHE = os.path.join(TOOLS, "jadx_src")     # fuentes decompiladas por hash de APK
LOOT = os.path.join(BASE, "loot")

JADX_VERSION = "1.5.0"
JADX_URL = "https://github.com/skylot/jadx/releases/download/v%s/jadx-%s.zip" % (JADX_VERSION, JADX_VERSION)

IS_WIN = platform.system().lower().startswith("win")

# Patrones de la "cacería rápida" (label, regex, modo). modo:
#   'match' -> el valor es lo que casó (o el grupo 1)
#   'line'  -> el valor es la cadena/línea que contiene la coincidencia (útil para palabras clave)
QUICK = [
    ("👽 flag",         r'ALIEN\{[^}]{1,80}\}', 'match'),
    ("🔑 password",     r'(?i)(?:password|passwd|pwd|clave|contrase|credential)', 'line'),
    ("🗝️ secret/token", r'(?i)(?:secret|api[_-]?key|apikey|token|auth[_-]?key|bearer|private[_-]?key)', 'line'),
    ("🌐 url",          r'https?://[^\s"\'<>)]+', 'match'),
    ("📡 ip:puerto",    r'\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b', 'match'),
]

# Ruido a descartar (namespaces/frameworks y placeholders).
NOISE = re.compile(r'(?i)(schemas\.android\.com|w3\.org|xmlpull\.org|apache\.org|'
                   r'java\.sun\.com|whatwg\.org|slf4j|kotlinlang\.org|'
                   r'ALIEN\{\.+\}|ALIEN\{\}|example\.com)')


# ------------------------------------------------------------------ jadx / java
def _jadx_bin():
    name = "jadx.bat" if IS_WIN else "jadx"
    p = os.path.join(JADX_DIR, "bin", name)
    return p if os.path.exists(p) else None


def has_java():
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=12)
        line = (r.stderr or r.stdout or "").splitlines()
        return True, (line[0].strip() if line else "java")
    except Exception:
        return False, ""


def status():
    java_ok, java_ver = has_java()
    return {
        "jadx_installed": _jadx_bin() is not None,
        "jadx_version": JADX_VERSION,
        "java": java_ok,
        "java_version": java_ver,
        "tools_dir": TOOLS,
    }


def install_jadx():
    """Descarga y extrae jadx en tools/jadx. Idempotente."""
    if _jadx_bin():
        return {"ok": True, "message": "jadx ya estaba instalado.", "bin": _jadx_bin()}
    os.makedirs(TOOLS, exist_ok=True)
    tmp_zip = os.path.join(TOOLS, "jadx_dl.zip")
    try:
        req = urllib.request.Request(JADX_URL, headers={"User-Agent": "AlienProbe"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        with open(tmp_zip, "wb") as f:
            f.write(data)
        # jadx.zip trae bin/ lib/ en la raiz
        if os.path.isdir(JADX_DIR):
            shutil.rmtree(JADX_DIR, ignore_errors=True)
        os.makedirs(JADX_DIR, exist_ok=True)
        with zipfile.ZipFile(tmp_zip) as z:
            z.extractall(JADX_DIR)
        try:
            os.remove(tmp_zip)
        except Exception:
            pass
        # permisos de ejecucion en unix
        b = _jadx_bin()
        if b and not IS_WIN:
            try:
                os.chmod(b, 0o755)
            except Exception:
                pass
        if b:
            return {"ok": True, "message": "jadx %s instalado." % JADX_VERSION, "bin": b}
        return {"ok": False, "message": "Se descargó jadx pero no encuentro el binario. Revisa %s" % JADX_DIR}
    except Exception as e:
        return {"ok": False, "message": "No pude descargar jadx (%s). El cazador seguirá funcionando en modo binario." % e}


# ------------------------------------------------------------------ APK
def resolve_apk(pkg, serial, adb_fn, apk_path=None):
    """Devuelve (ruta_apk, mensaje). Prioridad: ruta dada -> loot/ -> pull del dispositivo."""
    if apk_path:
        apk_path = apk_path.strip().strip('"')
        if os.path.exists(apk_path):
            return apk_path, "APK indicado por el usuario."
        return None, "La ruta indicada no existe: %s" % apk_path
    cached = os.path.join(LOOT, (pkg or "app") + ".apk")
    if os.path.exists(cached):
        return cached, "APK desde caché (loot/)."
    if not pkg:
        return None, "Sin APK: indica una ruta o selecciona una app para sacarla del dispositivo."
    # pull del dispositivo
    try:
        rc, out, _ = adb_fn(["shell", "pm", "path", pkg], serial)
        dev = ""
        for ln in (out or "").splitlines():
            if ln.startswith("package:"):
                dev = ln.split("package:", 1)[1].strip()
                break
        if not dev:
            return None, "No encontré el APK en el dispositivo (¿app instalada?)."
        os.makedirs(LOOT, exist_ok=True)
        adb_fn(["pull", dev, cached], serial)
        if os.path.exists(cached):
            return cached, "APK extraído del dispositivo."
        return None, "No pude hacer pull del APK."
    except Exception as e:
        return None, "Error sacando el APK: %s" % e


def _decompile(apk):
    """Decompila con jadx a fuente Java (cache por hash). Devuelve carpeta o None."""
    b = _jadx_bin()
    if not b:
        return None
    ok, _ = has_java()
    if not ok:
        return None
    try:
        h = hashlib.md5(open(apk, "rb").read()).hexdigest()[:12]
    except Exception:
        h = "apk"
    out = os.path.join(JADX_CACHE, h)
    src = os.path.join(out, "sources")
    if os.path.isdir(src) and os.listdir(src):
        return out
    os.makedirs(out, exist_ok=True)
    threads = str(os.cpu_count() or 4)
    try:
        # --no-res (no recursos) y --no-debug-info aceleran; -j usa todos los núcleos.
        subprocess.run([b, "-d", out, "--no-res", "--no-debug-info", "-j", threads, apk],
                       capture_output=True, text=True, timeout=420)
    except Exception:
        return None
    return out if os.path.isdir(src) and os.listdir(src) else (out if os.path.isdir(out) and os.listdir(out) else None)


# ------------------------------------------------------------------ corpus
_PRINTABLE = re.compile(rb'[\x20-\x7e]{4,}')


def _binary_lines(apk, cap=60000):
    """Extrae cadenas imprimibles de dex/recursos/assets del APK (sin jadx)."""
    lines = []
    try:
        with zipfile.ZipFile(apk) as z:
            for name in z.namelist():
                low = name.lower()
                if not (low.endswith(".dex") or low.endswith(".arsc")
                        or low.startswith("assets/") or low.endswith(".xml")
                        or low.endswith(".json") or low.endswith(".properties")):
                    continue
                try:
                    raw = z.read(name)
                except Exception:
                    continue
                for m in _PRINTABLE.findall(raw):
                    try:
                        s = m.decode("latin-1", "ignore")
                    except Exception:
                        continue
                    lines.append(("(binario) " + name, 0, s))
                    if len(lines) >= cap:
                        return lines
    except Exception:
        pass
    return lines


# Prefijos de librerías comunes: se descartan del cazador (son ruido; el interés es el
# código de la app). El paquete de la app SIEMPRE se incluye aunque empiece por alguno.
LIB_PREFIXES = (
    "androidx/", "android/", "com/google/", "kotlin/", "kotlinx/", "okhttp3/", "okio/",
    "org/", "retrofit2/", "javax/", "dagger/", "com/bumptech/", "io/", "net/",
    "j$/", "_COROUTINE/", "META-INF/", "com/squareup/", "soup/", "kotlinx_", "1/",
)


def _is_lib(rel, app_prefix):
    r = rel.replace("\\", "/")
    if app_prefix and r.startswith(app_prefix):
        return False
    return r.startswith(LIB_PREFIXES)


def _source_lines(srcdir, app_prefix=None, cap=300000):
    """Lee las fuentes .java decompiladas por jadx como (archivo, nºlínea, texto).

    Prioriza el paquete de la app (app_prefix) y descarta librerías conocidas, para que
    el cazador encuentre lo de la app y no se ahogue en androidx/kotlin/okhttp."""
    root = os.path.join(srcdir, "sources")
    if not os.path.isdir(root):
        root = srcdir
    app_files, other_files = [], []
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            if not f.endswith(".java"):
                continue
            fp = os.path.join(dp, f)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            if app_prefix and rel.startswith(app_prefix):
                app_files.append((fp, rel))
            elif not _is_lib(rel, app_prefix):
                other_files.append((fp, rel))
            # las librerías se descartan
    lines = []
    for fp, rel in app_files + other_files:      # app primero: nunca se corta
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                for i, ln in enumerate(fh, 1):
                    t = ln.strip()
                    if t:
                        lines.append((rel, i, t))
                        if len(lines) >= cap:
                            return lines
        except Exception:
            continue
    return lines


# ------------------------------------------------------------------ búsqueda
def _patterns_for(preset, query):
    if preset == "alien":
        return [("👽 flag", r'ALIEN\{[^}]{1,80}\}', 'match')]
    if preset == "creds":
        # Aterriza en la siembra de usuarios y en la lógica de login: revela las
        # credenciales en claro (ej. la línea con "alien", "area51") y campos como password_plain.
        return [("🔑 credencial",
                 r'(?i)(password|passwd|pwd|\bclave\b|\bpin\b|username|user_name|'
                 r'\blogin\b|credential|area51|\balien\b|"[a-z0-9_]{4,20}"\s*,\s*"[a-z0-9_]{4,20}")',
                 'line')]
    if preset == "custom":
        q = (query or "").strip()
        if not q:
            return []
        # por defecto literal (case-insensitive); si empieza y termina con / se trata como regex
        if len(q) >= 2 and q.startswith("/") and q.endswith("/"):
            return [("🔍 %s" % q, q[1:-1], 'line')]
        return [("🔍 %s" % q, "(?i)" + re.escape(q), 'line')]
    return QUICK  # quick


def hunt(pkg, serial, adb_fn, apk_path=None, preset="quick", query="", use_jadx=True):
    apk, msg = resolve_apk(pkg, serial, adb_fn, apk_path)
    if not apk:
        return {"ok": False, "message": msg, "results": [], "count": 0}

    srcdir = _decompile(apk) if use_jadx else None
    app_prefix = ((pkg or "").strip().replace(".", "/") or None)
    if app_prefix and not app_prefix.endswith("/"):
        app_prefix += "/"
    corpus = _source_lines(srcdir, app_prefix) if srcdir else _binary_lines(apk)
    mode = "jadx (fuente Java)" if srcdir else "binario (cadenas del APK)"

    pats = _patterns_for(preset, query)
    if not pats:
        return {"ok": False, "message": "Escribe algo para buscar.", "results": [], "count": 0, "apk": apk}

    compiled = []
    for label, rx, mode in pats:
        try:
            compiled.append((label, re.compile(rx), mode))
        except Exception:
            continue

    results = []
    seen = set()
    url_seen = set()          # dedup global de URLs/valores repetidos por todo el APK
    CAP = 300
    for (fname, lineno, text) in corpus:
        for label, rc, mode in compiled:
            m = rc.search(text)
            if not m:
                continue
            if mode == "line":
                value = text.strip()
            else:
                value = m.group(1) if (m.lastindex and m.group(1)) else m.group(0)
            if not value or NOISE.search(value):
                continue
            # URLs / valores 'match' repetidos por todo el binario -> uno solo
            if mode == "match" and label.startswith("🌐"):
                if value in url_seen:
                    continue
                url_seen.add(value)
            snippet = text if len(text) <= 200 else (text[:200] + "…")
            key = (label, value, fname, lineno, snippet[:60])
            if key in seen:
                continue
            seen.add(key)
            results.append({"type": label, "value": value, "file": fname,
                            "line": lineno, "snippet": snippet})
            if len(results) >= CAP:
                break
        if len(results) >= CAP:
            break

    # las flags primero, luego por tipo
    results.sort(key=lambda r: (0 if r["type"].startswith("👽") else 1, r["type"]))
    stats = {"lines": len(corpus), "files": len({c[0] for c in corpus})}
    return {"ok": True, "apk": apk, "apk_msg": msg, "mode": mode,
            "jadx": bool(srcdir), "stats": stats,
            "count": len(results), "results": results}


def decode_asset(pkg, serial, adb_fn, apk_path=None, name="assets/config.dat"):
    """Extrae un asset del APK y lo decodifica con el esquema del taller (Base64 + XOR 0x42).
    Sirve para F9 (assets/config.dat -> ALIEN{d3c0d3_m3}). Determinista, sin dispositivo."""
    import base64
    apk, msg = resolve_apk(pkg, serial, adb_fn, apk_path)
    if not apk:
        return {"ok": False, "message": msg}
    try:
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
            target = name if name in names else next((n for n in names if n.endswith(name) or n.endswith("config.dat")), None)
            if not target:
                return {"ok": False, "message": "No encontré %s en el APK." % name}
            raw = z.read(target)
    except Exception as e:
        return {"ok": False, "message": "No pude leer el asset: %s" % e}

    tries = []
    # Esquema del taller: Base64 y luego XOR 0x42
    try:
        dec = bytes(b ^ 0x42 for b in base64.b64decode(raw)).decode("utf-8", "replace")
        tries.append(("Base64 → XOR 0x42", dec))
    except Exception:
        pass
    # Variante: XOR 0x42 y luego Base64
    try:
        dec2 = bytes(b ^ 0x42 for b in raw)
        tries.append(("XOR 0x42 directo", dec2.decode("utf-8", "replace")))
    except Exception:
        pass
    flags = []
    for _lbl, txt in tries:
        flags += re.findall(r'ALIEN\{[^}]{1,80}\}', txt)
    return {"ok": True, "asset": target, "size": len(raw),
            "raw_preview": raw[:60].decode("latin-1", "replace"),
            "tries": tries, "flags": sorted(set(flags))}


_EXTRA_RE = re.compile(r'\.get(\w*?)Extra\s*\(\s*"([^"]+)"')
_HAS_RE = re.compile(r'\.hasExtra\s*\(\s*"([^"]+)"')


def _example_for(key, typ):
    k = key.lower()
    if "id" in k or typ in ("Int", "Long", "Short"):
        return "2"
    if typ == "Boolean":
        return "true"
    return ""


def _curated_extras(activity):
    a = (activity or "").lower()
    if "account" in a:
        return [{"key": "accountId", "type": "Int", "example": "2"}]
    return []


def activity_extras(pkg, serial, adb_fn, apk_path=None, activity=""):
    """Consulta qué extras (parámetros) lee una activity, decompilando su .java y buscando
    getXxxExtra("clave")/hasExtra(...). Si no hay jadx, cae a sugerencias del laboratorio."""
    apk, msg = resolve_apk(pkg, serial, adb_fn, apk_path)
    if not apk:
        return {"ok": False, "message": msg}
    srcdir = _decompile(apk)
    if not srcdir:
        return {"ok": True, "jadx": False, "extras": _curated_extras(activity),
                "note": "Sin jadx: sugerencias del laboratorio. Instala jadx para descubrir extras reales."}
    act = (activity or "").strip()
    if act.startswith("."):
        cls = (pkg or "") + act
    elif "." not in act:
        cls = (pkg or "") + "." + act
    else:
        cls = act
    rel = cls.replace(".", "/") + ".java"
    root = os.path.join(srcdir, "sources")
    if not os.path.isdir(root):
        root = srcdir
    fp = os.path.join(root, rel)
    extras = []
    if os.path.exists(fp):
        try:
            txt = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            txt = ""
        for m in _EXTRA_RE.finditer(txt):
            typ = m.group(1) or "Any"
            key = m.group(2)
            extras.append({"key": key, "type": typ, "example": _example_for(key, typ)})
        for m in _HAS_RE.finditer(txt):
            extras.append({"key": m.group(1), "type": "Any", "example": _example_for(m.group(1), "Any")})
    seen, ded = set(), []
    for e in extras:
        if e["key"] not in seen:
            seen.add(e["key"]); ded.append(e)
    if not ded:
        ded = _curated_extras(activity)
    return {"ok": True, "jadx": True, "file": rel, "extras": ded}


def context(pkg, serial, adb_fn, apk_path=None, file="", line=0, radius=3):
    """Devuelve una franja de líneas (line±radius) del archivo decompilado, para ver el
    hallazgo con su contexto (como un breakpoint). Solo con jadx (código Java)."""
    apk, msg = resolve_apk(pkg, serial, adb_fn, apk_path)
    if not apk:
        return {"ok": False, "message": msg}
    srcdir = _decompile(apk)
    if not srcdir:
        return {"ok": False, "message": "El contexto necesita jadx (código Java). Instálalo con el botón ⬇."}
    root = os.path.join(srcdir, "sources")
    if not os.path.isdir(root):
        root = srcdir
    safe = os.path.normpath(file).replace("\\", "/").lstrip("/")
    if ".." in safe.split("/"):
        return {"ok": False, "message": "Ruta inválida."}
    fp = os.path.join(root, safe)
    if not os.path.exists(fp):
        return {"ok": False, "message": "No encuentro el archivo (%s)." % file}
    try:
        with open(fp, encoding="utf-8", errors="ignore") as fh:
            allines = fh.read().splitlines()
    except Exception as e:
        return {"ok": False, "message": str(e)}
    radius = max(0, min(int(radius or 3), 40))
    line = int(line or 1)
    lo = max(1, line - radius)
    hi = min(len(allines), line + radius)
    out = [{"n": i, "text": allines[i - 1], "hit": (i == line)} for i in range(lo, hi + 1)]
    return {"ok": True, "file": safe, "from": lo, "to": hi, "total": len(allines), "lines": out}
