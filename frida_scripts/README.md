# frida_scripts — librería precargada de DynADB (10 scripts)

Scripts listos para instrumentar cualquier app (requieren frida-server corriendo y el venv con frida-tools).

| Script | Qué hace | MASVS |
|---|---|---|
| root_bypass.js | Bypass de root: hooks **nativos** (access/faccessat/stat/lstat/popen/openat) + **Java** (File.exists/Runtime.exec/RootBeer) + canary | RESILIENCE |
| ssl_unpin.js | Bypass de SSL/certificate pinning (OkHttp, SSLContext) | NETWORK |
| antifrida_off.js | Desactiva anti-Frida / anti-debug | RESILIENCE |
| crypto_trace.js | Traza Cipher/SecretKeySpec (claves y datos) | CRYPTO |
| method_trace.js | Traza todos los métodos de una clase (edita CLASE) | análisis |
| http_trace.js | Traza URLs HTTP(S) en runtime (sin proxy) | NETWORK |
| prefs_monitor.js | Muestra qué guarda la app en SharedPreferences | STORAGE |
| clipboard_monitor.js | Detecta datos copiados al portapapeles | STORAGE |
| webview_inspect.js | URLs y puentes JS de WebView | PLATFORM |
| flagsecure_off.js | Quita FLAG_SECURE (permite capturas) | PLATFORM |

Uso directo (CLI):
```
.venv\Scripts\frida -U -f <paquete> -l frida_scripts\root_bypass.js        (spawn)
.venv\Scripts\frida -U -n <paquete> -l frida_scripts\ssl_unpin.js          (attach)
```
Encadenar varios:  `-l root_bypass.js -l ssl_unpin.js -l antifrida_off.js`

Desde la GUI: pestaña **Frida** → los presets del `presets.json` usan estos scripts.
Cada preset trae `help` (qué hace) y `cli` (comando equivalente).
