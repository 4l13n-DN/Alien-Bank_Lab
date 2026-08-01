# 👽 0xAlienSec — Alien-Bank Lab

> "El conocimiento es libre, el crimen no."

Laboratorio de **seguridad móvil (OWASP MASVS / MASTG)** para aprender análisis **estático y dinámico** de aplicaciones Android, de punta a punta y en local. Incluye una app de banca vulnerable tipo **CTF**, una **plataforma de análisis dinámico** y un **servidor de API simulada** para el módulo de red.

Pensado para talleres: el alumno monta el entorno una vez y luego captura **11 flags** mapeadas a las categorías de OWASP MASVS.

## 🏴‍☠️ Descripción

El laboratorio se compone de tres piezas que trabajan juntas:

* **Alien-Bank** — Una app de banca deliberadamente insegura (el objetivo del CTF).
* **AlienProbe** — La plataforma de análisis dinámico (adb + Frida) con interfaz web.
* **ServidorAPI** — Un backend simulado para practicar captura de tráfico y SSL pinning.

Todo corre en local, en un entorno aislado, sobre un emulador con root. Ningún dato sale de tu máquina.

## 🧩 Componentes

### 📱 Alien-Bank — `/BancoAlien` (APK · CTF)

App Android de banca (`com.taller.bancoalien`) con **11 vulnerabilidades didácticas**, cada una mapeada a OWASP MASVS y a un CWE. Trae un **CTF Tracker** interno con puntaje (220 pts) y un material que se desbloquea al resolver el reto.

* **Qué demuestra:** credenciales hardcodeadas (CODE), datos en claro en SharedPreferences y SQLite (STORAGE), sin `FLAG_SECURE` (PLATFORM), IDOR y activity exportada (AUTH/PLATFORM), evasión de root y anti-Frida (RESILIENCE), asset ofuscado (CRYPTO) y tráfico HTTP en claro + SSL pinning evadible (NETWORK).
* **Credenciales de la app:** `alien` / `area51` (la gracia es descubrirlas, no que te las den).
* **Requisitos:** Android Studio (AGP 8, compileSdk 34, JDK 17), `minSdk 24`.

**Instalación / ejecución**

```
# Abrir la carpeta BancoAlien en Android Studio y pulsar Run ▶ (instala en el emulador)
# o generar el APK por consola:
cd BancoAlien
gradlew assembleDebug
# APK: app\build\outputs\apk\debug\app-debug.apk  -> arrástralo al emulador para instalar
```

### 🛰️ AlienProbe — `/DynADB` (plataforma de análisis dinámico)

Interfaz web local (Python + Flask) que orquesta **adb + Frida** para el análisis dinámico. Fija Frida 16.x y descarga `adb` de forma automática.

* **Qué hace:** evasión de controles (root / anti-Frida / SSL pinning), extracción de SharedPreferences y SQLite, prueba de componentes exportados e IDOR, captura de pantalla, lectura de tráfico OkHttp, un **Cazador** de secretos estático (jadx) y un **Informe** exportable a HTML/PDF con mapeo OWASP MASVS.
* **Requisitos:** Python 3.11 / 3.12 y un emulador **Genymotion x86_64 con root** (los ARM como Nox/LDPlayer no sirven con Frida).

**Ejecución**

```
cd DynADB
python run.py
# Abre la interfaz en http://127.0.0.1:8765
```

La primera vez crea su entorno virtual e instala dependencias solo.

### 🌐 ServidorAPI — `/ServidorAPI` (API simulada · módulo de red)

Servidor Flask local con **certificado fijo** que expone dos endpoints para el módulo de red (flags F10/F11):

* `http://<IP>:8888/promo` — HTTP **en claro** (se captura sin bypass).
* `https://<IP>:9443/secure/vault` — HTTPS con **certificate pinning** (requiere el unpinning de Frida o leer la respuesta dentro de la app).

* **Qué hace:** simula un recurso externo para practicar interceptación de tráfico y evasión de pinning. Cada respuesta incluye una flag.
* **Requisitos:** Python 3.

**Ejecución**

```
cd ServidorAPI
python run_server.py
# Crea el entorno, instala Flask + cryptography y arranca en los puertos 8888 / 9443
```

> Reparte la carpeta **con** `server.crt` y `server.key` (certificado fijo): así el pin es el mismo en todas las máquinas y la APK no necesita recompilarse.

## 🧰 Requisitos del laboratorio

* **Genymotion Desktop** (uso personal, gratis) con un dispositivo **Android 11 · API 30 · x86_64** (incluye root).
* **Python 3.11 / 3.12** (para AlienProbe y ServidorAPI).
* **Android Studio** (para compilar Alien-Bank; incluye `adb`).
* **Docker Desktop** (opcional, para el análisis estático con MobSF).

## 🚀 Puesta en marcha (resumen)

1. Enciende Genymotion y conéctalo: `adb connect <IP>:5555` → `adb devices`.
2. Compila e instala **Alien-Bank** desde Android Studio (Run ▶).
3. Arranca **AlienProbe**: `python run.py` → `http://127.0.0.1:8765`.
4. Arranca el **ServidorAPI**: `python run_server.py` (para las flags de red).
5. En AlienProbe: selecciona el dispositivo y la app, inicia frida-server y empieza a capturar flags.

La guía completa (presentación + laboratorio paso a paso con las 11 flags) está en `GUIA_MAESTRA_AlienBank.html`.

## 🎯 Reto

* **11 flags** con formato `ALIEN{...}`, repartidas por dificultad (Nivel 1 a 3).
* **220 puntos** en total; la última flag desbloquea el material del taller.
* Cobertura OWASP MASVS: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE y RESILIENCE.

## ⚠️ Uso ético y legal

Este laboratorio es **exclusivamente educativo**. Ejecútalo en un entorno aislado y **solo** sobre Alien-Bank o aplicaciones propias, de laboratorio o con **autorización escrita** del titular. La banca real, únicamente bajo contrato de pentest. El uso indebido es responsabilidad de quien lo realiza.

---

Created by [0xAlienSec](https://github.com/4l13n-DN)
Cybersecurity | Red Teaming | Development
