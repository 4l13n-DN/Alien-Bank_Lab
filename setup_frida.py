#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup_frida.py - Deja frida-server listo en el dispositivo, sin adivinar nada.
DEBE ejecutarse con el Python del venv (donde esta frida-tools):
    Windows:  .venv\\Scripts\\python setup_frida.py
    Linux/Mac: .venv/bin/python setup_frida.py

Hace: lee la version de frida del venv -> detecta la arquitectura del device por adb ->
descarga frida-server-<ver>-android-<arch> de GitHub -> lo descomprime -> lo sube ->
chmod -> lo ejecuta como root. Verifica con 'frida-ps -U'.
"""
import sys, os, subprocess, lzma, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import dynadb

ARCH_MAP = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm"}

def frida_version():
    try:
        import frida
        return frida.__version__
    except Exception:
        return None

def main():
    ap_run = "--no-run" not in sys.argv

    ver = frida_version()
    if not ver:
        print("[X] frida no esta en este Python. Ejecuta con el venv:")
        print(r"    .venv\Scripts\python setup_frida.py   (Windows)")
        print( "    .venv/bin/python setup_frida.py       (Linux/Mac)")
        print("    (y antes: python run.py, que instala frida-tools en el venv)")
        return 1
    print("[i] Version de frida (venv): %s" % ver)

    # Resolver adb sin prompt interactivo: config > PATH > argumento
    cfg = dynadb.load_config()
    adb_path = cfg.get("adb") or dynadb.ADB
    if adb_path and os.path.exists(adb_path):
        dynadb.ADB = adb_path
    elif not dynadb.ADB or dynadb.ADB == "adb":
        import shutil
        w = shutil.which("adb")
        if w:
            dynadb.ADB = w
    print("[i] adb: %s" % dynadb.ADB)

    rc, abi, _ = dynadb.adb(["shell", "getprop", "ro.product.cpu.abi"])
    abi = (abi or "").strip()
    arch = ARCH_MAP.get(abi)
    if not arch:
        print("[X] Arquitectura no reconocida: '%s'. Conecta el device (adb devices)." % abi)
        return 1
    print("[i] Arquitectura del device: %s -> android-%s" % (abi, arch))

    name = "frida-server-%s-android-%s" % (ver, arch)
    url  = "https://github.com/frida/frida/releases/download/%s/%s.xz" % (ver, name)
    xz   = os.path.join(BASE, name + ".xz")
    out  = os.path.join(BASE, "frida-server")

    print("[i] Descargando %s ..." % url)
    try:
        urllib.request.urlretrieve(url, xz)
    except Exception as e:
        print("[X] Error descargando (%s)." % e)
        print("    Baja manualmente %s desde https://github.com/frida/frida/releases" % (name + ".xz"))
        return
    print("[i] Descomprimiendo ...")
    with lzma.open(xz) as f, open(out, "wb") as o:
        o.write(f.read())

    print("[i] Subiendo al dispositivo ...")
    rc, msg, err = dynadb.adb(["push", out, "/data/local/tmp/frida-server"])
    print("    " + (msg or err).strip())
    # chmod y VERIFICAR que se aplico (algunos Nox/BusyBox lo silencian). Reintentar.
    for attempt in range(3):
        dynadb.adb(["shell", "su", "-c", "chmod 755 /data/local/tmp/frida-server"], serial=None)
        rc, ls, _ = dynadb.adb(["shell", "ls", "-l", "/data/local/tmp/frida-server"], serial=None)
        ls = (ls or "").strip()
        # Esperamos algo como '-rwxr-xr-x ...'
        if ls.startswith("-rwx"):
            print("    [+] permisos OK: %s" % ls.split()[0])
            break
        print("    [!] permisos no aplicados (intento %d): %s" % (attempt+1, ls.split()[0] if ls else "(vacio)"))
    else:
        print("    [X] no pude poner permisos de ejecucion. Hazlo a mano:")
        print('        adb shell "su -c \'chmod 755 /data/local/tmp/frida-server\'"')
        return 1

    if not ap_run:
        print("[OK] frida-server subido. Para ejecutarlo:")
        print('    adb shell su -c "/data/local/tmp/frida-server &"')
        return

    print("[i] Iniciando frida-server como root. DEJA ESTA VENTANA ABIERTA.")
    print("    En OTRA terminal (con el venv activo):  frida-ps -U   y luego el bypass.")
    try:
        subprocess.call([dynadb.ADB, "shell", "su", "-c", "/data/local/tmp/frida-server"])
    except KeyboardInterrupt:
        print("\n[i] frida-server detenido.")

if __name__ == "__main__":
    main()
