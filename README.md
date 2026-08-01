# 👽 0xAlienSec — Alien-Bank Lab

Laboratorio de **seguridad móvil (OWASP MASVS / MASTG)** para aprender análisis **estático y dinámico** de aplicaciones Android, de punta a punta y en local. Incluye una app de banca vulnerable tipo **CTF (ya compilada)**, la **plataforma de análisis dinámico AlienProbe** y un **servidor de API simulada** para el módulo de red.

Pensado para talleres: montas el entorno una vez y capturas **11 flags** mapeadas a las categorías de OWASP MASVS. La app viene lista para instalar — **no necesitas Android Studio**.

## 🏴‍☠️ Descripción

Tres piezas que trabajan juntas, todo en local y en un entorno aislado (ningún dato sale de tu máquina):

* **AlienProbe** — La plataforma de análisis dinámico (adb + Frida) con interfaz web. *(está en la raíz del repositorio)*.
* **Alien-Bank** — La app de banca deliberadamente insegura, el objetivo del CTF. *(APK compilada en `/APP`)*.
* **ServidorAPI** — Un backend simulado para practicar captura de tráfico y SSL pinning. *(en `/ServidorAPI`)*.

## 🗂️ Estructura del repositorio

```
/                 → AlienProbe (run.py, gui.py, index.html, core/, frida_scripts/, presets.json, ...)
/APP              → Alien-Bank.apk (la app ya COMPILADA, lista para instalar)
/ServidorAPI      → servidor de API simulada (run_server.py, mock_api.py, server.crt/key)
README.md · LICENSE
```

---

## 🛰️ AlienProbe — plataforma de análisis dinámico

Interfaz web local (Python + Flask) que orquesta **adb + Frida** desde el navegador. No necesitas memorizar comandos: cada módulo es guiado, con ayuda contextual, tooltips y explicaciones paso a paso.

**Arranca sola:** la primera vez crea su entorno virtual, instala dependencias, **descarga `adb`** (platform-tools oficial de Google) si no lo tienes y **fija Frida 16.x** de forma automática. Si copias la carpeta a otra PC, `run.py` **repara el entorno** por sí mismo.

```
python run.py
# Abre la interfaz en http://127.0.0.1:8765
```

**Requisitos:** Python 3.11 / 3.12 y un emulador **Genymotion x86_64 con root** (los ARM como Nox/LDPlayer no funcionan bien con Frida).

### Panel de control (barra lateral)

Siempre visible, es donde preparas la sesión:

* **adb** — detecta o fija la ruta del ejecutable y comprueba que responde.
* **Dispositivo** — refresca la lista, **auto-detecta** emuladores por sus puertos típicos o conecta manualmente por `host:port`.
* **App objetivo** — lista las apps instaladas (con filtro), **instala un APK** desde tu disco y selecciona el paquete a analizar.
* **Barra de estado** — chips en vivo de `adb · device · root · frida · target · modo` para saber de un vistazo si todo está listo.

### Módulos (pestañas)

| Módulo | Qué hace |
|---|---|
| 🔍 **Recon** | Huella de la app: versión, `debuggable`, uid, permisos y modo de acceso (root / no-root). El punto de partida. |
| 🧩 **Componentes** | Lista activities, servicios y receivers, y **resalta los exportados** (la superficie de ataque). |
| 💾 **Almacenamiento** | Extrae **SharedPreferences + SQLite** (con WAL) y **escanea secretos** en claro; los muestra en un panel de hallazgos. |
| 🎯 **Launch / IDOR** | Lanza activities con **extras arbitrarios** para probar acceso indebido (**IDOR**) y componentes exportados sin login. |
| 📸 **Captura** | Screenshot del dispositivo — demuestra la falta de `FLAG_SECURE`. |
| 📜 **Logcat** | Logs de la app en vivo para seguir su comportamiento. |
| ⚡ **Frida** | **29 presets** de instrumentación *data-driven*: bypass de root, **SSL unpinning**, anti-Frida off, combo banca, **lector de red** (OkHttp), trazas y más — en modo **spawn** o **attach**. |
| 🕵️ **Cazador** | Análisis **estático con jadx**: busca claves, secretos y flags dentro del APK. Presets `quick / alien / creds / custom`, contexto por líneas y **decodificador** de assets ofuscados. Instala jadx solo y te pide el APK (o usa el que extrajiste). |
| ⚡ **ADB** | **Consola ADB gráfica + administrador de apps** (ver abajo). |
| 📋 **Informe** | **Ledger acumulativo** de hallazgos con severidad, cobertura **OWASP MASVS / CWE** y recomendaciones. Exporta a **HTML / PDF**. |
| 🔌 **Cómo conectar** | Asistente para conectar Genymotion, Nox, AVD o un dispositivo físico. |

### ⚡ Módulo ADB — consola gráfica + administrador de apps

Habla con el dispositivo por ADB sin aprenderte los comandos. Dos bloques guiados:

**Paso 1 · Consola de comandos.** Ejecuta comandos ADB desde un catálogo organizado en **Básicas / Avanzadas / Especiales** (`devices`, `getprop`, `pm list packages`, `dumpsys`, `ps`, `ip addr`, `settings`, `input keyevent`, `su`, `reboot`…) o escribe el tuyo a mano. La respuesta del dispositivo aparece al instante.

**Paso 2 · Administrador de apps.** Lista las apps instaladas (con filtro; solo de usuario `-3` o también las del sistema) y, por cada una, botones de acción:

* ⤓ **Extraer APK** — `pm path` + `adb pull` del `base.apk`; lo guarda en el PC y te da el enlace de descarga.
* 📋 **Info** — versión, permisos y rutas de la app.
* ▶ **Abrir** — lanza la app en el dispositivo.
* ⏹ **Force-stop** — la cierra por completo.
* 🧹 **Borrar datos** — la deja como recién instalada. *(destructivo, pide confirmación)*
* 🗑 **Desinstalar** — la quita del dispositivo. *(destructivo, pide confirmación)*

> El APK extraído se puede analizar directo en el **Cazador** o subir a MobSF.

### Cómo funciona por dentro

AlienProbe es una **SPA** (`index.html`) servida por un backend **Flask** (`gui.py`) que envuelve un núcleo (`dynadb.py` + `core/`) sobre `adb` y los *bindings* de **Frida**. Los presets de instrumentación viven en `presets.json` (editables), los scripts de Frida en `frida_scripts/`, y la ayuda didáctica en `ui_help.json`. Todo corre en `127.0.0.1` — nada sale de tu equipo.

---

## 📱 Alien-Bank — `/APP` (APK · CTF · ya compilada)

App Android de banca (`com.taller.bancoalien`) con **11 vulnerabilidades didácticas**, cada una mapeada a OWASP MASVS y a un CWE. Trae un **CTF Tracker** interno con puntaje (220 pts) y un material que se desbloquea al resolver el reto.

* **No requiere Android Studio:** la app ya viene compilada en `/APP`. Solo se instala.
* **Qué demuestra:** credenciales hardcodeadas (CODE), datos en claro en SharedPreferences y SQLite (STORAGE), sin `FLAG_SECURE` (PLATFORM), IDOR y activity exportada (AUTH/PLATFORM), evasión de root y anti-Frida (RESILIENCE), asset ofuscado (CRYPTO) y tráfico HTTP en claro + SSL pinning evadible (NETWORK).
* **Acceso:** las credenciales están *dentro* de la app — descubrirlas es el primer reto (pista: revisa el código con jadx o el **Cazador** de AlienProbe). Aquí no se regalan.

**Instalación (con el emulador ya encendido)**

```
# Opción 1: arrastra el .apk de la carpeta APP sobre la ventana de Genymotion.
# Opción 2, por consola:
adb install APP/Alien-Bank.apk
```

## 🌐 ServidorAPI — `/ServidorAPI` (API simulada · módulo de red)

Servidor Flask local con **certificado fijo** que expone dos endpoints para el módulo de red (flags F10/F11):

* `http://<IP>:8888/promo` — HTTP **en claro** (se captura sin bypass).
* `https://<IP>:9443/secure/vault` — HTTPS con **certificate pinning** (se lee tras el unpinning de Frida o hookeando la respuesta dentro de la app).

* **Qué hace:** simula un recurso externo para practicar interceptación de tráfico y evasión de pinning. Cada respuesta incluye una flag.
* **Requisitos:** Python 3.

**Ejecución**

```
cd ServidorAPI
python run_server.py
# Crea el entorno, instala Flask + cryptography y arranca en los puertos 8888 / 9443
```

> El certificado (`server.crt` / `server.key`) es **fijo**: por eso el pin es el mismo en todas las máquinas y la APK no necesita recompilarse. En la app, el engranaje ⚙️ del login permite fijar la IP del servidor.

## 🧰 Requisitos del laboratorio

* **Genymotion Desktop** (uso personal, gratis) con un dispositivo **Android 11 · API 30 · x86_64** (incluye root).
* **Python 3.11 / 3.12** (para AlienProbe y ServidorAPI).
* **adb** (opcional: AlienProbe lo descarga solo).
* **Docker Desktop** (opcional, para el análisis estático con MobSF).
* **Android Studio** — **NO es necesario**: la app ya viene compilada. Solo si quieres recompilarla desde el código.

## 🚀 Puesta en marcha (resumen)

1. Enciende Genymotion y conéctalo: `adb connect <IP>:5555` → `adb devices`.
2. Instala la app: `adb install APP/Alien-Bank.apk` (o arrástrala al emulador).
3. Arranca **AlienProbe**: `python run.py` → `http://127.0.0.1:8765`.
4. Arranca el **ServidorAPI**: `python run_server.py` (para las flags de red).
5. En AlienProbe: selecciona el dispositivo y la app, inicia frida-server y empieza a capturar flags.

## 🎯 El reto

* **11 flags** con formato `ALIEN{...}`, repartidas por dificultad (Nivel 1 a 3).
* **220 puntos** en total; solo al capturar **todas** las flags se desbloquea el material del taller.
* Cobertura OWASP MASVS: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE y RESILIENCE.
* Al completarlo desbloqueas la **Guía PRO**, con todas las técnicas, comandos y el solucionario.

## ⚠️ Uso ético y legal

Este laboratorio es **exclusivamente educativo**. Ejecútalo en un entorno aislado y **solo** sobre Alien-Bank o aplicaciones propias, de laboratorio o con **autorización escrita** del titular. La banca real, únicamente bajo contrato de pentest. El uso indebido es responsabilidad de quien lo realiza.

---

Created by [0xAlienSec](https://github.com/4l13n-DN)
Cybersecurity | Red Teaming | Development
