#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diag_frida.py - Diagnostico automatico del bypass de Frida (solo lee, no cambia nada).
Correr en tu Windows con Nox conectado, usando el venv:
    .venv\\Scripts\\python diag_frida.py
Dice EXACTAMENTE cual es el problema y como arreglarlo.
"""
import sys, os
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import dynadb

SERVER = "/data/local/tmp/frida-server"
OK, BAD, WARN = "  [OK] ", "  [X]  ", "  [!]  "
def line(): print("-" * 60)

def main():
    print("=" * 60); print("  DIAGNOSTICO FRIDA — AlienProbe"); print("=" * 60)
    verdict = []

    # 0) adb
    dynadb.ADB = dynadb.resolve_adb("adb")
    cfg = dynadb.load_config(); serial = cfg.get("serial")
    print("adb        :", dynadb.ADB)
    print("serial cfg :", serial or "(ninguno)")
    rc, out, err = dynadb.adb(["version"])
    if rc != 0: print(BAD, "adb no responde"); verdict.append("Instala/confirma adb."); _end(verdict)
    line()

    # 1) device conectado
    rc, out, _ = dynadb.adb(["devices"])
    devs = [l.split("\t")[0] for l in out.splitlines()[1:] if "\tdevice" in l]
    if not devs:
        print(BAD, "No hay device en 'adb devices'.")
        verdict.append("Conecta Nox: adb connect 127.0.0.1:62025 (o 62001).")
        _end(verdict)
    if not serial or serial not in devs: serial = devs[0]
    print(OK, "device:", serial)

    # 2) root
    rc, idout, _ = dynadb.adb(["shell", "su", "-c", "id"], serial); idout = (idout or "").strip()
    rooted = "uid=0" in idout
    print((OK if rooted else BAD), "root (su -c id):", idout or "(sin salida)")
    if not rooted: verdict.append("El device no da root. En Nox activa root en Ajustes; en AVD usa 'adb root'.")

    # 3) arquitectura
    rc, abi, _ = dynadb.adb(["shell", "getprop", "ro.product.cpu.abi"], serial); abi = (abi or "").strip()
    rc, api, _ = dynadb.adb(["shell", "getprop", "ro.build.version.sdk"], serial); api = (api or "").strip()
    print(OK, "abi:", abi, "| API:", api)
    if api and api.isdigit() and int(api) <= 25:
        print(WARN, "Android <=7 (API %s) + emulador x86/ARM = entorno fragil para Frida." % api)
        verdict.append("Considera un AVD Google APIs Android 11 x86_64 (mas fiable que Nox).")

    # 4) frida en el venv
    try:
        import frida; fver = frida.__version__
        print(OK, "frida (venv):", fver)
    except Exception:
        print(BAD, "frida NO esta en este Python. Corre con .venv\\Scripts\\python (venv 3.12).")
        verdict.append("Usa el venv: .venv\\Scripts\\python diag_frida.py")
        _end(verdict)

    # 5) binario en device + permisos
    rc, ls, _ = dynadb.adb(["shell", "su", "-c", "ls -l %s" % SERVER], serial); ls = (ls or "").strip()
    if not ls or ls.startswith("ls:"):
        print(BAD, "frida-server NO esta en el device.")
        verdict.append("Sube el server: .venv\\Scripts\\python setup_frida.py")
        _end(verdict)
    perms = ls.split()[0] if ls else "?"
    print((OK if perms.startswith("-rwx") else WARN), "permisos:", perms, "(" + ls[:50] + "...)")

    # 6) EJECUTA? (noexec)
    rc, ver, _ = dynadb.adb(["shell", "su", "-c", "%s --version" % SERVER], serial); ver = (ver or "").strip()
    if fver in ver:
        print(OK, "ejecuta: frida-server --version ->", ver)
    else:
        print(BAD, "NO ejecuta. Salida:", ver or "(vacio)")
        if "denied" in ver.lower() or not ver:
            print(WARN, ">>> CAUSA RAIZ PROBABLE: /data/local/tmp montado NOEXEC")
            verdict.append("NOEXEC: remonta con  adb shell su -c 'mount -o remount,exec /data'  "
                           "o reubica el binario a /data/local/fs. (El fix §5.1 ya lo hace en la GUI.)")

    # 7) frida-server corriendo como root?
    rc, ps, _ = dynadb.adb(["shell", "su", "-c", "ps | grep frida-server"], serial); ps = (ps or "").strip()
    if ps:
        print(OK, "frida-server en ejecucion:", ps.splitlines()[0][:60])
    else:
        print(WARN, "frida-server NO esta corriendo ahora (hay que arrancarlo).")
        verdict.append("Arranca: .venv\\Scripts\\python frida_up.py  (o el boton de la GUI).")

    # 8) el host lo ALCANZA?
    try:
        dev = frida.get_usb_device(timeout=6)
        procs = dev.enumerate_processes()
        print(OK, "host alcanza el server (frida-ps): %d procesos" % len(procs))
        print()
        print(">>> Frida OK. Deberia funcionar el bypass de root. Si aun falla,")
        print("    el problema es que la app usa un check no cubierto (ver §D3 de ESTADO_FRIDA).")
    except Exception as e:
        print(BAD, "el host NO alcanza el server:", str(e)[:90])
        if "jailed" in str(e).lower() or "gadget" in str(e).lower():
            print(WARN, ">>> 'jailed/Gadget' = frida-server no corre como root/alcanzable.")
        verdict.append("Arranca frida-server (frida_up.py) y reintenta.")
    _end(verdict)

def _end(verdict):
    print(); print("=" * 60); print("  VEREDICTO"); print("=" * 60)
    if not verdict:
        print("  Todo OK.")
    else:
        for i, v in enumerate(verdict, 1):
            print("  %d) %s" % (i, v))
    print()
    sys.exit(0)

if __name__ == "__main__":
    main()
