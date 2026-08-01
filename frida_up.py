#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frida_up.py - Deja frida-server corriendo tras CADA arranque del emulador.
Un comando por boot:  .venv\\Scripts\\python frida_up.py   (Windows)
                       .venv/bin/python frida_up.py        (Linux/Mac)
Hace: matar previos -> chmod 755 -> probar ejecucion (detecta noexec y remonta) ->
arrancar detached (setsid -D) -> verificar desde el host con frida.
Asume que el binario ya esta en /data/local/tmp (si no, corre setup_frida.py una vez).
"""
import sys, os, time
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import dynadb
try:
    import frida
except Exception:
    frida = None

SERVER = "/data/local/tmp/frida-server"

def su(cmd, serial=None):
    return dynadb.adb(["shell", "su", "-c", cmd], serial)

def main():
    dynadb.ADB = dynadb.resolve_adb("adb")
    serial = None
    cfg = dynadb.load_config()
    serial = cfg.get("serial")

    # 1) matar frida-server previos (sin pkill -f, que se auto-mata)
    su("for p in $(pgrep -f %s); do kill -9 $p 2>/dev/null; done; pkill -9 -x frida-server 2>/dev/null; true" % SERVER, serial)

    # 2) chmod y verificar permisos
    su("chmod 755 %s" % SERVER, serial)
    rc, ls, _ = dynadb.adb(["shell", "su", "-c", "ls -l %s" % SERVER], serial)
    ls = (ls or "").strip()
    print("permisos:", ls or "(no existe -> corre setup_frida.py primero)")
    if not ls or ls.startswith("ls:"):
        print("[X] frida-server no esta en el device. Ejecuta setup_frida.py una vez.")
        sys.exit(2)

    # 3) probar EJECUCION real (detecta noexec)
    rc, ver, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % SERVER], serial)
    ver = (ver or "").strip()
    if (not ver) or ("denied" in ver.lower()) or ("not executable" in ver.lower()):
        print("[!] no ejecuta (posible noexec en /data/local/tmp). Remontando /data exec...")
        su("mount -o remount,exec /data", serial)
        rc, ver, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % SERVER], serial)
        ver = (ver or "").strip()
        if (not ver) or ("denied" in ver.lower()):
            # Fallback: reubicar a /data/local (a veces exec cuando /tmp no)
            su("cp %s /data/local/fs && chmod 755 /data/local/fs" % SERVER, serial)
            alt = "/data/local/fs"
            rc, ver, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % alt], serial)
            ver = (ver or "").strip()
            if ver and "denied" not in ver.lower():
                globals()["SERVER"] = alt
                print("[i] usando ruta alterna:", alt)
    print("frida-server --version:", ver or "(sin salida)")

    # 4) arrancar detached
    su("setsid %s -D >/dev/null 2>&1 < /dev/null &" % SERVER, serial)
    time.sleep(2.0)

    # 5) verificar desde el host
    ok = False
    if frida:
        try:
            dev = frida.get_usb_device(timeout=6)
            dev.enumerate_processes()
            ok = True
        except Exception as e:
            print("[!] el host NO alcanza el server:", e)
    else:
        print("[!] frida no esta en este Python (usa el venv).")
    print("=" * 48)
    print("frida-server arriba y alcanzable:", "SI ✅" if ok else "NO ❌")
    if ok:
        print("Ya puedes usar los presets Frida / el bypass de root.")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
