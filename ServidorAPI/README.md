# Servidor mock — Alien-Bank (módulo de RED, MASVS-NETWORK)

API simulada, local y gratuita, para practicar **captura de tráfico** y **SSL pinning** sobre Alien-Bank.
Levanta dos endpoints y cada uno entrega una flag en la respuesta (la flag NO va dentro del APK).

- **HTTP en claro**  →  `http://<IP>:8888/promo`  → flag *cleartext* (se captura con un proxy, sin bypass).
- **HTTPS con pinning** →  `https://<IP>:9443/secure/vault` → flag *pinning* (requiere el preset **Bypass SSL pinning** de AlienProbe).

> Puertos **no comunes** (8888 / 9443) para evitar choques con otros servicios del alumno.

## Requisitos

- **Python 3** instalado (Windows). Nada más: el arranque crea el entorno e instala las librerías solo.

## Arrancar (un comando)

```
python run_server.py
```

o en Windows, doble clic en **`iniciar_servidor.bat`**.

La primera vez crea `.venv` e instala **Flask** y **cryptography**. Al iniciar imprime algo así:

```
HTTP  (cleartext):  http://192.168.56.1:8888/promo
HTTPS (pinned):     https://192.168.56.1:9443/secure/vault

Como lo alcanza el emulador:
  - AVD (Android Studio):  10.0.2.2   (por defecto, no cambies nada)
  - Genymotion:            10.0.3.2
  - Dispositivo/otro PC:   192.168.56.1   (IP LAN de esta maquina)

En la app: abre el engranaje del login -> campo 'Servidor' y escribe la IP de arriba.
```

## Cómo se conecta la APK (sin recompilar)

La APK **ya viene lista**: los puertos (8888 / 9443) y el PIN del certificado están horneados.
Lo único que puede cambiar es la **IP**, y eso se ajusta **dentro de la app**:

1. Abre Alien-Bank → toca el **engranaje ⚙️** de la pantalla de login.
2. Escribe la **IP** del PC donde corre este servidor (AVD = `10.0.2.2`, Genymotion = `10.0.3.2`,
   dispositivo real = IP LAN del PC).
3. Pulsa **Probar** → debe decir **"Conectado ✓"** en HTTP y HTTPS.
4. La IP **queda guardada** en la app (`shared_prefs/alien_net.xml`); solo se cambia si hace falta.

Así la dirección puede variar en cada máquina sin tocar el código ni volver a compilar.

## Certificado FIJO (clave para que el PIN sea igual para todos)

Este servidor usa un **certificado fijo** (`server.crt` / `server.key`, validez 10 años). Su PIN es el
que está horneado en la APK. **Reparte `server.crt` y `server.key` junto a esta carpeta** a cada alumno:
así todos sirven el mismo certificado → el mismo PIN → la APK pre-compilada funciona en todos.

> Si borras `server.crt` / `server.key`, se regenera OTRO certificado con OTRO pin y la APK dejaría de
> validar el endpoint pinned. No los borres salvo que vayas a re-hornear el PIN en `build.gradle`.

PIN actual (ya en `app/build.gradle`):

```
VAULT_PIN = "sha256/BSNiGlcyO6RuDgzgY7fCydMOxbEf+ANCHUV7C+xVOJY="
```

## Firewall

La primera vez, Windows pedirá permitir Python en la red. **Acepta** (red privada), o el emulador no
podrá alcanzar los puertos 8888 / 9443.

## Cómo se resuelven las flags (didáctico)

- **cleartext (F10):** con el proxy activo (mitmproxy / Burp) ves la petición a `/promo` en claro y la
  flag en la respuesta. También se ve con el preset *Trazar URLs HTTP* de AlienProbe.
- **pinning (F11):** con el proxy, `/secure/vault` falla (el pinning corta el MITM). Ejecuta el preset
  **Bypass SSL pinning** (Frida) y repite: ahora el proxy lee la respuesta y aparece la flag.

## Archivos

- `run_server.py` — arranque (venv + dependencias + ejecución).
- `mock_api.py` — el servidor (endpoints, puertos 8888/9443, certificado y pin).
- `iniciar_servidor.bat` — lanzador para Windows.
- `server.crt` / `server.key` — **certificado fijo** (se reparte con el server; NO borrar).

## Ético / legal

Servidor de laboratorio, local y de práctica. Solo para Alien-Bank u apps con autorización.
