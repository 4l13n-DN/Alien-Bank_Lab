# -*- coding: utf-8 -*-
"""
core/report_log.py - Ledger de hallazgos ACUMULATIVO de AlienProbe.

Cada accion que se hace sobre la app (bypass de root, extraer almacenamiento, IDOR,
captura, etc.) se registra aqui con su lectura de "app real", categoria OWASP MASVS,
CWE, severidad e impacto. Al final se renderiza un informe de analisis dinamico
profesional en Markdown, descargable como insumo.

No depende de frida ni adb: solo guarda entradas y las formatea.
"""
import time
import threading
import os
import base64
import html as _html

_LOCK = threading.Lock()
_ENTRIES = []          # lista de dicts (hallazgos en orden cronologico)
_META = {"pkg": None, "device": None, "started": time.strftime("%Y-%m-%d %H:%M:%S")}

# Orden y etiqueta de severidades
_SEV = ["Crítica", "Alta", "Media", "Baja", "Info"]


def set_meta(pkg=None, device=None):
    with _LOCK:
        if pkg:
            _META["pkg"] = pkg
        if device:
            _META["device"] = device


def get_meta():
    with _LOCK:
        return dict(_META)


# --------------------------------------------------------------------------
# CATALOGO: por cada tecnica/preset, la lectura profesional + "en una app real".
# clave -> plantilla de hallazgo. gui.py llama log_action(clave, pkg, evidencia).
# --------------------------------------------------------------------------
CATALOG = {
    "root_bypass": {
        "titulo": "Detección de root evadible (control de resiliencia insuficiente)",
        "tecnica": "Instrumentación dinámica con Frida (spawn + hooks Java/nativos)",
        "masvs": "MASVS-RESILIENCE", "cwe": "CWE-919", "severidad": "Media",
        "que_se_hizo": "Se lanzó la app con Frida hookeando la detección de root "
                       "(File.exists, Runtime.exec, RootBeer y la clase propia RootDetection.isDeviceRooted()).",
        "hallazgo": "El diálogo 'dispositivo rooteado' se neutraliza forzando el chequeo a devolver false; la app abre normalmente en un dispositivo rooteado.",
        "app_real": "En una banca real, una detección de root que se evade con un hook indica que no hay defensa en profundidad: un atacante con el dispositivo rooteado puede instrumentar la app, leer memoria, saltarse controles de cliente y extraer secretos. El control debe endurecerse (SafetyNet/Play Integrity server-side, ofuscación, checks múltiples) y NUNCA ser la única barrera.",
        "remediacion": "No confiar solo en detección local; validar integridad del lado servidor (Play Integrity API), combinar múltiples señales, ofuscar y detectar instrumentación (Frida) de forma redundante.",
    },
    "antifrida_off": {
        "titulo": "Anti-Frida / anti-debug evadible",
        "tecnica": "Frida (hook a la clase FridaDetection.isFridaPresent())",
        "masvs": "MASVS-RESILIENCE", "cwe": "CWE-919", "severidad": "Media",
        "que_se_hizo": "Se forzó isFridaPresent()/anti-debug a false para revelar funciones ocultas por la app.",
        "hallazgo": "La comprobación anti-Frida (archivo frida-server, puerto 27042, isDebuggerConnected) se anula con un hook.",
        "app_real": "Las protecciones anti-instrumentación de solo cliente siempre son evadibles por un atacante con root. Sirven para elevar el costo, no para garantizar seguridad. Si la lógica sensible (límites, validaciones, tokens) vive solo en el cliente, queda expuesta.",
        "remediacion": "Mover la lógica sensible al servidor; usar atestación de integridad; no basar decisiones de seguridad en checks locales.",
    },
    "banking_combo": {
        "titulo": "Bypass combinado (root + SSL pinning + anti-Frida)",
        "tecnica": "Frida (varios scripts al spawn)",
        "masvs": "MASVS-RESILIENCE", "cwe": "CWE-919", "severidad": "Alta",
        "que_se_hizo": "Se aplicaron simultáneamente bypass de root, unpinning de SSL y bypass anti-Frida al arrancar la app.",
        "hallazgo": "Con un solo preset se anulan las tres barreras de resiliencia de la app.",
        "app_real": "Demuestra que las defensas de cliente encadenadas caen juntas frente a un atacante con instrumentación. Habilita interceptar tráfico TLS y manipular la app en runtime.",
        "remediacion": "Defensa en profundidad y validación server-side; asumir el cliente como hostil.",
    },
    "ssl_unpin": {
        "titulo": "SSL Pinning evadible (intercepción de tráfico TLS)",
        "tecnica": "Frida (unpinning) + proxy MITM",
        "masvs": "MASVS-NETWORK", "cwe": "CWE-295", "severidad": "Alta",
        "que_se_hizo": "Se hookeó la validación de certificados/pinning para permitir un proxy interceptor.",
        "hallazgo": "El pinning se anula; el tráfico HTTPS pasa a ser legible/modificable vía proxy.",
        "app_real": "Permite ver y alterar TODO el tráfico con la API: endpoints, tokens, cuerpos de peticiones, respuestas. Revela si viaja PII/credenciales, si hay endpoints sin autorización, IDOR de servidor, etc. Es la puerta a auditar la API.",
        "remediacion": "El pinning es una capa, no la única. Autorización robusta en el servidor; no confiar en que el canal no será interceptado.",
    },
    "http_trace": {
        "titulo": "Trazado de URLs/endpoints en runtime",
        "tecnica": "Frida (hooks a HttpURLConnection/OkHttp)",
        "masvs": "MASVS-NETWORK", "cwe": "CWE-200", "severidad": "Media",
        "que_se_hizo": "Se registraron las URLs y peticiones HTTP que la app realiza en vivo, sin proxy.",
        "hallazgo": "Se listan endpoints, hosts y parámetros usados por la app.",
        "app_real": "Mapea la superficie de API real (incluidos endpoints internos/no documentados), detecta HTTP en claro, y pistas de parámetros manipulables. Base para probar la API directamente.",
        "remediacion": "Forzar HTTPS, no exponer endpoints internos, no enviar datos sensibles por GET/URL.",
    },
    "capture_traffic": {
        "titulo": "Captura de tráfico con proxy (MITM)",
        "tecnica": "Proxy (mitmproxy) + SSL unpin",
        "masvs": "MASVS-NETWORK", "cwe": "CWE-319", "severidad": "Alta",
        "que_se_hizo": "Se enrutó el tráfico de la app por un proxy para inspeccionar peticiones/respuestas.",
        "hallazgo": "Se captura el tráfico de la app (tras unpinning).",
        "app_real": "Evidencia directa de qué datos viajan y cómo. Permite encontrar tokens reutilizables, falta de autorización, respuestas con PII de más, y validar controles del servidor.",
        "remediacion": "Autorización server-side por objeto y usuario; minimizar datos en respuestas; TLS estricto.",
    },
    "crypto_trace": {
        "titulo": "Trazado de operaciones criptográficas",
        "tecnica": "Frida (hooks a Cipher/MessageDigest/KeyStore)",
        "masvs": "MASVS-CRYPTO", "cwe": "CWE-327", "severidad": "Media",
        "que_se_hizo": "Se interceptaron llamadas de cifrado/hash para ver algoritmos, claves y datos en claro.",
        "hallazgo": "Se observan algoritmos y material de clave usados por la app.",
        "app_real": "Revela criptografía débil (ECB, MD5/SHA1, claves hardcodeadas, IV fijos) y datos justo antes de cifrarse. Común encontrar 'cifrado casero' trivial de revertir.",
        "remediacion": "Usar algoritmos fuertes (AES-GCM), claves en Android Keystore, no hardcodear secretos.",
    },
    "prefs_monitor": {
        "titulo": "Monitor de SharedPreferences en runtime",
        "tecnica": "Frida (hook a SharedPreferences)",
        "masvs": "MASVS-STORAGE", "cwe": "CWE-312", "severidad": "Media",
        "que_se_hizo": "Se registró en vivo qué claves/valores escribe/lee la app en SharedPreferences.",
        "hallazgo": "Se observan datos que la app persiste (posibles tokens/PII en claro).",
        "app_real": "Muestra secretos guardados en claro en el momento de escribirse (tokens de sesión, PIN, flags). Estos persisten y son recuperables con root o backup.",
        "remediacion": "EncryptedSharedPreferences; no persistir secretos; ligar cifrado al Keystore.",
    },
    "storage": {
        "titulo": "Datos sensibles en almacenamiento local sin cifrar",
        "tecnica": "Volcado de /data/data con root (o run-as) + escaneo de secretos",
        "masvs": "MASVS-STORAGE", "cwe": "CWE-312", "severidad": "Alta",
        "que_se_hizo": "Se extrajo el sandbox de la app (shared_prefs, databases, files) y se escaneó en busca de secretos.",
        "hallazgo": "Se hallaron datos legibles en SharedPreferences y/o SQLite sin cifrado.",
        "app_real": "Es uno de los hallazgos más frecuentes en banca/fintech: tokens de sesión/JWT, PII (nombre, documento, cuenta), movimientos e incluso credenciales en claro dentro de prefs XML o SQLite sin SQLCipher. Con el dispositivo perdido/rooteado o vía backup, todo es recuperable.",
        "remediacion": "Cifrar en reposo (EncryptedSharedPreferences, SQLCipher), minimizar lo almacenado, no guardar credenciales, borrar al cerrar sesión.",
    },
    "launch_idor": {
        "titulo": "IDOR — acceso a datos de otro usuario",
        "tecnica": "Invocación directa de Activity con identificador manipulado (am start)",
        "masvs": "MASVS-AUTH", "cwe": "CWE-639", "severidad": "Alta",
        "que_se_hizo": "Se lanzó una pantalla de cuenta con un identificador ajeno (accountId manipulado).",
        "hallazgo": "Se accede a datos de una cuenta que no pertenece al usuario, sin control de autorización.",
        "app_real": "IDOR es de las vulnerabilidades más críticas en banca: si el servidor (o la app) no valida que el objeto pertenece al usuario, cambiar un id expone cuentas, movimientos o documentos de terceros. A escala, fuga masiva de datos.",
        "remediacion": "Autorización por objeto y por usuario en el SERVIDOR; nunca confiar en identificadores del cliente.",
    },
    "exported_admin": {
        "titulo": "Componente exportado sin autenticación",
        "tecnica": "Invocación directa de Activity exportada (am start)",
        "masvs": "MASVS-PLATFORM", "cwe": "CWE-926", "severidad": "Alta",
        "que_se_hizo": "Se lanzó directamente una Activity exportada (panel admin) sin pasar por login.",
        "hallazgo": "Se abre funcionalidad privilegiada sin autenticación por estar exportada en el manifest.",
        "app_real": "Cualquier app instalada en el teléfono puede invocar ese componente. Habilita saltarse el login, llegar a paneles internos o disparar acciones sensibles. Muy común por `android:exported=true` mal puesto.",
        "remediacion": "exported=false salvo necesidad; exigir permisos/verificación de llamante; no poner lógica sensible en componentes accesibles.",
    },
    "components": {
        "titulo": "Superficie de ataque: componentes exportados",
        "tecnica": "Inspección del manifest (dumpsys package)",
        "masvs": "MASVS-PLATFORM", "cwe": "CWE-926", "severidad": "Media",
        "que_se_hizo": "Se enumeraron Activities/Services/Receivers exportados de la app.",
        "hallazgo": "Se listaron componentes accesibles desde otras apps.",
        "app_real": "Cada componente exportado es una entrada potencial. Se revisa cuáles disparan acciones sin auth (deep links, receivers, activities internas).",
        "remediacion": "Minimizar exportados; validar intents y permisos; proteger deep links.",
    },
    "static_scan": {
        "titulo": "Secretos / URLs embebidos en el binario",
        "tecnica": "Quick-scan estático del APK (strings de dex/recursos/assets)",
        "masvs": "MASVS-CODE", "cwe": "CWE-798", "severidad": "Media",
        "que_se_hizo": "Se extrajo el APK y se escanearon sus strings en busca de secretos, claves y URLs.",
        "hallazgo": "Se hallaron secretos/claves y/o endpoints embebidos en el binario.",
        "app_real": "Todo lo que va en el APK es público: API keys, secretos y endpoints hardcodeados son recuperables por cualquiera que decompile. Habilita abuso de servicios de terceros y mapeo de la API.",
        "remediacion": "No hardcodear secretos (usar backend/secret manager); ofuscar (R8); rotar claves expuestas.",
    },
    "debuggable": {
        "titulo": "Aplicación marcada como debuggable",
        "tecnica": "Inspección de flags del paquete (dumpsys)",
        "masvs": "MASVS-RESILIENCE", "cwe": "CWE-489", "severidad": "Media",
        "que_se_hizo": "Se detectó el flag android:debuggable en el paquete instalado.",
        "hallazgo": "La app permite depuración (jdwp), acceso vía run-as y adjuntar debuggers.",
        "app_real": "Una build de producción debuggable permite a un atacante depurar la app, leer memoria y usar run-as para acceder al sandbox sin root. Es un error de release grave.",
        "remediacion": "Compilar release con debuggable=false; validar en el pipeline de build.",
    },
    "allow_backup": {
        "titulo": "Respaldo de datos habilitado (allowBackup)",
        "tecnica": "Inspección de flags del paquete (dumpsys)",
        "masvs": "MASVS-STORAGE", "cwe": "CWE-530", "severidad": "Media",
        "que_se_hizo": "Se detectó android:allowBackup habilitado.",
        "hallazgo": "Los datos de la app pueden extraerse vía 'adb backup' sin root.",
        "app_real": "Con allowBackup=true, cualquiera con acceso al dispositivo (o adb) puede extraer el sandbox de la app —incluidos tokens/PII— sin root. Debe deshabilitarse en apps con datos sensibles.",
        "remediacion": "android:allowBackup=false o reglas de backup que excluyan datos sensibles.",
    },
    "storage_diff": {
        "titulo": "Rastreo de escritura de datos (diff de almacenamiento)",
        "tecnica": "Snapshot del sandbox antes/después de una acción (md5 por archivo)",
        "masvs": "MASVS-STORAGE", "cwe": "CWE-312", "severidad": "Media",
        "que_se_hizo": "Se comparó el almacenamiento de la app antes y después de una acción (login/transferencia) para localizar qué archivo/clave se escribe.",
        "hallazgo": "Se identificó exactamente dónde persiste la app los datos tras la acción (token de sesión, PII, etc.).",
        "app_real": "Localiza el punto exacto donde se guarda el token de sesión o PII; permite verificar si se cifra en reposo y si se limpia al cerrar sesión. Técnica clave para auditar el manejo de secretos.",
        "remediacion": "Cifrar en reposo (EncryptedSharedPreferences/SQLCipher), minimizar persistencia y borrar al hacer logout.",
    },
    "hook_builder": {
        "titulo": "Instrumentación puntual (hook a método)",
        "tecnica": "Frida (hook dinámico a clase.método, registrar o forzar retorno)",
        "masvs": "MASVS-RESILIENCE", "cwe": "CWE-919", "severidad": "Info",
        "que_se_hizo": "Se hookeó un método concreto para observar sus argumentos/retorno o forzar su valor.",
        "hallazgo": "La lógica del método es observable y manipulable en tiempo de ejecución.",
        "app_real": "Cualquier decisión tomada en el cliente (validaciones, límites, precios, feature flags, checks de seguridad) puede observarse y alterarse con un hook. Demuestra por qué la lógica sensible no debe residir solo en el cliente.",
        "remediacion": "Validar en el servidor; no confiar en controles de cliente; ofuscar y atestar integridad (Play Integrity).",
    },
    "providers": {
        "titulo": "Content Provider expuesto / consultable",
        "tecnica": "Enumeración y consulta de ContentProviders (content query --uri)",
        "masvs": "MASVS-PLATFORM", "cwe": "CWE-926", "severidad": "Alta",
        "que_se_hizo": "Se enumeraron las authorities de ContentProviders de la app y se consultaron vía content://.",
        "hallazgo": "Se accedió a datos a través de un ContentProvider sin control de acceso adecuado.",
        "app_real": "Un ContentProvider exportado o con permisos débiles permite a cualquier app leer/escribir datos de la víctima, y si construye SQL con la URI/selección sin parametrizar, habilita inyección SQL. Es un vector clásico y de alto impacto en apps que comparten datos.",
        "remediacion": "exported=false salvo necesidad; permisos de lectura/escritura por provider; parametrizar consultas; validar y limitar proyección/selección.",
    },
    "screenshot": {
        "titulo": "Ausencia de FLAG_SECURE (capturas de pantalla permitidas)",
        "tecnica": "Captura de pantalla del contenido sensible (screencap)",
        "masvs": "MASVS-PLATFORM", "cwe": "CWE-200", "severidad": "Baja",
        "que_se_hizo": "Se capturó la pantalla mostrando información sensible (saldo/datos).",
        "hallazgo": "La app permite screenshots de pantallas sensibles (no usa FLAG_SECURE).",
        "app_real": "Sin FLAG_SECURE, la info sensible aparece en capturas, en la vista de apps recientes (thumbnail) y es capturable por malware con permiso de pantalla. En banca se espera FLAG_SECURE en saldos/datos.",
        "remediacion": "Aplicar WindowManager.LayoutParams.FLAG_SECURE en pantallas sensibles.",
    },
    "signature_info": {
        "titulo": "Información de firma del APK",
        "tecnica": "Inspección de firma (dumpsys/apksigner)",
        "masvs": "MASVS-CODE", "cwe": "CWE-693", "severidad": "Info",
        "que_se_hizo": "Se revisó el certificado de firma (debug vs release) del APK.",
        "hallazgo": "Se identificó el esquema/certificado de firma.",
        "app_real": "Una firma debug o v1-only en producción es señal de mala higiene de release y facilita re-empaquetado.",
        "remediacion": "Firmar release con esquema v2/v3, proteger la clave, verificar firma en runtime si aplica.",
    },
    "pull_apk": {
        "titulo": "Extracción del APK para análisis estático",
        "tecnica": "adb pull del APK instalado",
        "masvs": "MASVS-CODE", "cwe": "CWE-200", "severidad": "Info",
        "que_se_hizo": "Se extrajo el APK del dispositivo para decompilar (jadx) y revisar assets/recursos.",
        "hallazgo": "Se obtuvo el APK; habilita análisis estático (código, secretos hardcodeados, assets ofuscados).",
        "app_real": "El APK siempre es extraíble: hay que asumir que el atacante lo tiene. Se buscan credenciales/API keys hardcodeadas, endpoints, y 'cifrado' débil de assets.",
        "remediacion": "No hardcodear secretos; ofuscar (R8); asumir el binario como público.",
    },
    "full_audit": {
        "titulo": "Auditoría dinámica completa",
        "tecnica": "recon + componentes + storage + captura + informe",
        "masvs": "MASVS (varios)", "cwe": "-", "severidad": "Info",
        "que_se_hizo": "Se ejecutó la batería completa de análisis dinámico sobre la app.",
        "hallazgo": "Ver hallazgos individuales registrados.",
        "app_real": "Barrido estándar de un pentest móvil dinámico.",
        "remediacion": "Ver cada hallazgo.",
    },
}


def log_action(key, pkg=None, evidencia="", extra=None):
    """Registra un hallazgo a partir del catalogo. `evidencia` = texto real observado
    (p.ej. secretos hallados, salida del comando). `extra` = dict para sobreescribir campos."""
    tpl = CATALOG.get(key)
    if not tpl:
        tpl = {"titulo": key, "tecnica": "-", "masvs": "-", "cwe": "-",
               "severidad": "Info", "que_se_hizo": "", "hallazgo": "",
               "app_real": "", "remediacion": ""}
    entry = dict(tpl)
    entry["key"] = key
    entry["pkg"] = pkg or _META.get("pkg")
    entry["evidencia"] = (evidencia or "").strip()
    if extra:
        entry.update(extra)
    return add(entry)


def add(entry):
    with _LOCK:
        e = dict(entry)
        e.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
        e.setdefault("severidad", "Info")
        e.setdefault("titulo", "(sin título)")
        _ENTRIES.append(e)
        return len(_ENTRIES)


def add_note(texto):
    """Nota manual del analista."""
    return add({"titulo": "Nota del analista", "tecnica": "manual", "masvs": "-",
                "cwe": "-", "severidad": "Info", "que_se_hizo": "", "hallazgo": texto,
                "app_real": "", "remediacion": "", "key": "note"})


def items():
    with _LOCK:
        return list(_ENTRIES)


def clear():
    with _LOCK:
        _ENTRIES.clear()


def _counts():
    c = {s: 0 for s in _SEV}
    for e in items():
        c[e.get("severidad", "Info")] = c.get(e.get("severidad", "Info"), 0) + 1
    return c


def render_md(pkg=None, device=None):
    """Informe de análisis dinámico profesional en Markdown."""
    meta = get_meta()
    pkg = pkg or meta.get("pkg") or "(app)"
    device = device or meta.get("device") or "(dispositivo)"
    entries = items()
    now = time.strftime("%Y-%m-%d %H:%M")
    counts = _counts()

    md = []
    md.append("# Informe de Análisis Dinámico Móvil")
    md.append("")
    md.append("**Aplicación:** `%s`  " % pkg)
    md.append("**Dispositivo / entorno:** %s  " % device)
    md.append("**Herramienta:** AlienProbe · 0xAlienSec (adb + Frida)  ")
    md.append("**Marco de referencia:** OWASP MASVS / MASTG  ")
    md.append("**Fecha:** %s  " % now)
    md.append("**Analista:** __________________")
    md.append("")
    md.append("> **Aviso ético/legal.** Análisis realizado sobre una app de laboratorio / con "
              "autorización del titular, en entorno aislado. La banca real solo bajo contrato de pentest.")
    md.append("")
    md.append("---")
    md.append("")

    # Resumen ejecutivo
    md.append("## 1. Resumen ejecutivo")
    md.append("")
    total = len(entries)
    md.append("Se ejecutó un análisis dinámico sobre `%s` mediante instrumentación (Frida) y "
              "acceso al sandbox (adb/root). Se registraron **%d** observaciones/hallazgos." % (pkg, total))
    md.append("")
    md.append("| Severidad | Cantidad |")
    md.append("|---|---|")
    for s in _SEV:
        if counts.get(s):
            md.append("| %s | %d |" % (s, counts[s]))
    md.append("")

    # Metodología
    md.append("## 2. Metodología")
    md.append("")
    md.append("Análisis dinámico siguiendo OWASP MASTG: preparación del entorno (emulador rooteado + "
              "frida-server), evasión de controles de resiliencia para observar el comportamiento real, "
              "y evaluación de almacenamiento, comunicación, plataforma, autenticación y criptografía. "
              "Cada acción se registró con su lectura de impacto en un escenario real.")
    md.append("")

    # Hallazgos
    md.append("## 3. Hallazgos detallados")
    md.append("")
    if not entries:
        md.append("_(Aún no se han registrado acciones.)_")
        md.append("")
    for i, e in enumerate(entries, 1):
        md.append("### 3.%d %s" % (i, e.get("titulo", "")))
        md.append("")
        md.append("- **Severidad:** %s" % e.get("severidad", "Info"))
        if e.get("masvs") and e["masvs"] != "-":
            md.append("- **OWASP MASVS:** %s%s" % (e["masvs"],
                      ("  ·  **CWE:** %s" % e["cwe"]) if e.get("cwe") and e["cwe"] != "-" else ""))
        if e.get("tecnica") and e["tecnica"] != "-":
            md.append("- **Técnica:** %s" % e["tecnica"])
        md.append("- **Momento:** %s" % e.get("ts", ""))
        if e.get("que_se_hizo"):
            md.append("- **Qué se hizo:** %s" % e["que_se_hizo"])
        if e.get("hallazgo"):
            md.append("- **Hallazgo:** %s" % e["hallazgo"])
        if e.get("evidencia"):
            md.append("- **Evidencia observada:**")
            md.append("")
            md.append("```")
            md.append(e["evidencia"][:2000])
            md.append("```")
        if e.get("app_real"):
            md.append("- **Lectura en una app real:** %s" % e["app_real"])
        if e.get("remediacion"):
            md.append("- **Remediación:** %s" % e["remediacion"])
        md.append("")

    # Cobertura MASVS
    md.append("## 4. Cobertura OWASP MASVS")
    md.append("")
    cats = ["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
            "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE"]
    seen = set(e.get("masvs", "") for e in entries)
    md.append("| Categoría MASVS | ¿Evaluada? |")
    md.append("|---|---|")
    for c in cats:
        md.append("| %s | %s |" % (c, "✔ Sí" if any(c in s for s in seen) else "—"))
    md.append("")
    md.append("---")
    md.append("")
    md.append("_Informe generado por AlienProbe · 0xAlienSec — análisis dinámico móvil (OWASP MASVS/MASTG)._")
    md.append("")
    return "\n".join(md)


_SEV_HTML = {"Crítica": "#e5484d", "Alta": "#f76808", "Media": "#f5b74e",
             "Baja": "#39d0d8", "Info": "#8a9a91"}


def _img_data_uri(path):
    try:
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                b = base64.b64encode(f.read()).decode("ascii")
            return "data:image/png;base64," + b
    except Exception:
        pass
    return None


def render_html(pkg=None, device=None):
    """Informe de análisis dinámico en HTML con estilo (imprimible a PDF desde el navegador).
    Embebe las capturas de pantalla asociadas a cada hallazgo."""
    meta = get_meta()
    pkg = pkg or meta.get("pkg") or "(app)"
    device = device or meta.get("device") or "(dispositivo)"
    entries = items()
    counts = _counts()
    now = time.strftime("%Y-%m-%d %H:%M")
    e = _html.escape

    rows_sev = "".join("<tr><td><span class='dot' style='background:%s'></span>%s</td><td>%d</td></tr>"
                       % (_SEV_HTML.get(s, "#888"), s, counts[s]) for s in _SEV if counts.get(s))

    cards = []
    for i, en in enumerate(entries, 1):
        col = _SEV_HTML.get(en.get("severidad", "Info"), "#888")
        parts = ["<div class='card' style='border-left-color:%s'>" % col]
        parts.append("<div class='ch'><span class='n'>%d</span><b>%s</b>"
                     "<span class='sev' style='color:%s;border-color:%s'>%s</span>"
                     % (i, e(en.get("titulo", "")), col, col, e(en.get("severidad", "Info"))))
        if en.get("masvs") and en["masvs"] != "-":
            parts.append("<span class='masvs'>%s%s</span>" % (e(en["masvs"]),
                         (" · " + e(en["cwe"])) if en.get("cwe") and en["cwe"] != "-" else ""))
        parts.append("<span class='ts'>%s</span></div>" % e(en.get("ts", "")))
        if en.get("tecnica") and en["tecnica"] != "-":
            parts.append("<div class='f'><b>Técnica:</b> %s</div>" % e(en["tecnica"]))
        if en.get("que_se_hizo"):
            parts.append("<div class='f'><b>Qué se hizo:</b> %s</div>" % e(en["que_se_hizo"]))
        if en.get("hallazgo"):
            parts.append("<div class='f'><b>Hallazgo:</b> %s</div>" % e(en["hallazgo"]))
        if en.get("evidencia"):
            parts.append("<pre>%s</pre>" % e(en["evidencia"][:2000]))
        uri = _img_data_uri(en.get("img_path"))
        if uri:
            parts.append("<div class='f'><b>Evidencia (captura):</b></div><img class='shot' src='%s'/>" % uri)
        if en.get("app_real"):
            parts.append("<div class='f real'><b>En una app real:</b> %s</div>" % e(en["app_real"]))
        if en.get("remediacion"):
            parts.append("<div class='f'><b>Remediación:</b> %s</div>" % e(en["remediacion"]))
        parts.append("</div>")
        cards.append("".join(parts))

    cats = ["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
            "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE"]
    seen = set(x.get("masvs", "") for x in entries)
    covered = {c: any(c in s for s in seen) for c in cats}
    ncov = sum(1 for c in cats if covered[c])
    masvs_badges = "".join(
        "<span class='mb %s'>%s</span>" % ("on" if covered[c] else "off", c.replace("MASVS-", ""))
        for c in cats)
    cov = "".join("<tr><td>%s</td><td>%s</td></tr>" %
                  (c, "✔ Evaluada" if covered[c] else "— No cubierta") for c in cats)

    total = len(entries)
    denom = total or 1
    # KPIs por severidad
    sev_chips = "".join(
        "<div class='kpi'><div class='kn' style='color:%s'>%d</div><div class='kl'>%s</div></div>"
        % (_SEV_HTML.get(s, "#888"), counts.get(s, 0), s) for s in _SEV if counts.get(s))
    # Barra apilada por severidad
    sev_bar = "".join(
        "<span style='width:%.2f%%%%;background:%s' title='%s: %d'></span>"
        % (counts.get(s, 0) * 100.0 / denom, _SEV_HTML.get(s, "#888"), s, counts.get(s, 0))
        for s in _SEV if counts.get(s))
    # Top remediaciones (prioridad Crítica/Alta/Media, únicas)
    recs, seenr = [], set()
    for en in entries:
        if en.get("severidad") in ("Crítica", "Alta", "Media") and en.get("remediacion"):
            r = en["remediacion"]
            if r not in seenr:
                seenr.add(r)
                recs.append((en.get("severidad"), en.get("titulo", ""), r))
    top_recs = "".join(
        "<li><b style='color:%s'>%s</b> — %s</li>" % (_SEV_HTML.get(s, "#888"), e(t), e(r))
        for s, t, r in recs[:8]) or "<li class='t2'>Sin remediaciones de prioridad registradas todavía.</li>"

    return """<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Informe · %(pkg)s · AlienProbe</title>
<style>
 :root{--bg:#0b1210;--pan:#121b17;--pan2:#0e1714;--bd:#22322a;--tx:#e6efe9;--t2:#9fb3a8;--ac:#38e07b;--ac2:#57ff97}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--tx);
  font-family:'Segoe UI',system-ui,sans-serif;line-height:1.55}
 .wrap{max-width:980px;margin:0 auto;padding:0 26px 70px}
 .band{margin:0 -26px 8px;padding:26px 26px 22px;background:
   radial-gradient(900px 300px at 30%% -20%%, rgba(56,224,123,.18), transparent 60%%), linear-gradient(180deg,#0e1a15,#0b1210);
   border-bottom:1px solid var(--bd)}
 .badge{display:inline-block;font-family:monospace;font-size:11px;letter-spacing:2px;color:var(--ac2);
   border:1px solid rgba(56,224,123,.4);border-radius:20px;padding:4px 11px;background:rgba(56,224,123,.06)}
 h1{font-size:25px;margin:8px 0 4px} h2{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--bd);padding-bottom:6px}
 .meta{color:var(--t2);font-size:13.5px} .meta b{color:var(--tx)}
 .kpis{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 6px}
 .kpi{background:var(--pan);border:1px solid var(--bd);border-radius:12px;padding:10px 16px;min-width:96px;text-align:center}
 .kpi .kn{font-size:24px;font-weight:800} .kpi .kl{font-size:11px;color:var(--t2);text-transform:uppercase;letter-spacing:1px}
 .kpi.tot .kn{color:var(--ac2)}
 .bar{display:flex;height:12px;border-radius:20px;overflow:hidden;background:var(--pan);border:1px solid var(--bd);margin:6px 0 4px}
 .bar span{display:block;height:100%%}
 .mbs{margin:10px 0} .mb{display:inline-block;font-family:monospace;font-size:11px;border-radius:20px;padding:3px 10px;margin:3px 6px 3px 0;border:1px solid var(--bd)}
 .mb.on{color:#04120a;background:var(--ac);border-color:var(--ac);font-weight:700} .mb.off{color:var(--t2);opacity:.6}
 .aviso{background:rgba(245,183,78,.1);border:1px solid #3a2f16;border-left:3px solid #f5b74e;
  padding:10px 12px;border-radius:8px;margin:14px 0;font-size:13px}
 table{border-collapse:collapse;width:100%%;margin:10px 0;font-size:13.5px}
 th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left} th{background:var(--pan)}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%%;margin-right:7px;vertical-align:middle}
 .card{background:var(--pan);border:1px solid var(--bd);border-left:3px solid #888;border-radius:10px;padding:14px 16px;margin:12px 0}
 .ch{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
 .ch .n{background:var(--ac);color:#04120a;font-weight:700;border-radius:6px;padding:1px 8px;font-size:13px}
 .ch b{font-size:15px} .sev{font-size:11px;font-weight:700;border:1px solid;border-radius:999px;padding:1px 8px}
 .masvs{font-size:11px;color:var(--t2);font-family:monospace} .ts{font-size:11px;color:var(--t2);margin-left:auto}
 .f{font-size:13.5px;margin:5px 0} .f.real{color:var(--ac)} .t2{color:var(--t2)}
 ol.recs li{margin:5px 0;font-size:13.5px}
 pre{background:#08110d;border:1px solid var(--bd);border-radius:7px;padding:9px 11px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
 .shot{max-width:340px;border:1px solid var(--bd);border-radius:8px;margin:6px 0;display:block}
 .noprint{margin:12px 0} .noprint button{background:var(--ac);color:#04120a;border:0;border-radius:8px;padding:9px 16px;font-weight:700;cursor:pointer}
 footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--bd);color:var(--t2);font-size:12px}
 @media print{ body{background:#fff;color:#111} .band{background:#f3faf5} .card,pre,table th,.kpi,.bar{background:#fff}
  .noprint{display:none} .f.real{color:#0a7a3a} .mb.on{background:#0a7a3a;color:#fff} a{color:#111} }
</style></head><body><div class="wrap">
 <div class="band">
   <span class="badge">HACKER MENTOR · 0xAlienSec</span>
   <h1>Informe de Análisis de Seguridad Móvil</h1>
   <div class="meta"><b>Aplicación:</b> %(pkg)s &nbsp;·&nbsp; <b>Entorno:</b> %(dev)s &nbsp;·&nbsp;
     <b>Herramienta:</b> AlienProbe (adb + Frida) &nbsp;·&nbsp; <b>Marco:</b> OWASP MASVS / MASTG &nbsp;·&nbsp; <b>Fecha:</b> %(now)s</div>
   <div class="kpis">
     <div class="kpi tot"><div class="kn">%(total)d</div><div class="kl">Hallazgos</div></div>
     %(sev_chips)s
     <div class="kpi"><div class="kn" style="color:var(--ac2)">%(ncov)d/7</div><div class="kl">Áreas MASVS</div></div>
   </div>
   <div class="bar">%(sev_bar)s</div>
   <div class="mbs">%(masvs_badges)s</div>
 </div>
 <div class="noprint"><button onclick="window.print()">🖨️ Imprimir / Guardar como PDF</button></div>
 <div class="aviso"><b>Aviso ético/legal.</b> Análisis sobre app de laboratorio o con autorización escrita del titular, en entorno aislado. La banca real solo bajo contrato de pentest.</div>
 <h2>1. Resumen ejecutivo</h2>
 <p>Se realizó un análisis dinámico sobre <code>%(pkg)s</code> mediante instrumentación (Frida) y acceso al sandbox (adb/root). Se registraron <b>%(total)d</b> hallazgos, cubriendo <b>%(ncov)d de 7</b> áreas de OWASP MASVS. El detalle, con evidencia y remediación, está en la sección 4.</p>
 <table><tr><th>Severidad</th><th>Cantidad</th></tr>%(rows_sev)s</table>
 <h2>2. Recomendaciones prioritarias</h2>
 <ol class="recs">%(top_recs)s</ol>
 <h2>3. Metodología</h2>
 <p>Análisis dinámico siguiendo OWASP MASTG: preparación del entorno (emulador rooteado + frida-server), evasión de controles de resiliencia para observar el comportamiento real, y evaluación de almacenamiento, comunicación, plataforma, autenticación y criptografía. Cada hallazgo se registró con su técnica, evidencia y su lectura en una app real.</p>
 <h2>4. Hallazgos detallados</h2>
 %(cards)s
 <h2>5. Cobertura OWASP MASVS</h2>
 <table><tr><th>Categoría</th><th>Estado</th></tr>%(cov)s</table>
 <footer>Informe generado por <b>AlienProbe</b> · 0xAlienSec — análisis dinámico móvil (OWASP MASVS/MASTG). Reutilizable para cualquier app autorizada.</footer>
</div></body></html>""" % {
        "pkg": e(pkg), "dev": e(device), "now": now, "total": len(entries), "ncov": ncov,
        "rows_sev": rows_sev or "<tr><td>—</td><td>0</td></tr>",
        "sev_chips": sev_chips, "sev_bar": sev_bar or "<span style='width:100%%;background:#22322a'></span>",
        "masvs_badges": masvs_badges, "top_recs": top_recs,
        "cards": "".join(cards) or "<p><i>Aún no se han registrado acciones.</i></p>",
        "cov": cov,
    }
