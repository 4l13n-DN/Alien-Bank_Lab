# -*- coding: utf-8 -*-
"""
core/access.py - Capa de acceso al almacenamiento privado de una app.

Detecta el modo de acceso disponible y expone read_app_file() para que el resto
del tool (storage, report) funcione igual en los 3 escenarios:

  - root  : emulador/fisico rooteado (adb root o su -c). Lee CUALQUIER app (debug o release).
  - runas : app debuggable. adb exec-out run-as <pkg> cat <path>.
  - none  : no hay root ni debuggable. Sugerir 'patch' (repackaging).

No reimprime logica de adb: usa dynadb.adb() como transporte.
"""
import os
import dynadb


def adb_root_available(serial=None):
    """True si el dispositivo admite shell root (adb root da uid=0 o whoami=root)."""
    rc, out, _ = dynadb.adb(["shell", "whoami"], serial)
    if rc == 0 and (out or "").strip() == "root":
        return True
    # Algunos emuladores exigenen 'adb root' primero; probamos su -c id como fallback.
    rc, out, _ = dynadb.adb(["shell", "su", "-c", "id"], serial)
    return rc == 0 and "uid=0" in (out or "")


def app_is_debuggable(pkg, serial=None):
    d = dynadb.info_data(pkg, serial)
    return bool(d and d.get("debuggable"))


def get_access_mode(pkg, serial=None, prefer=None):
    """Devuelve 'root' | 'runas' | 'none'. Si prefer=auto|root|runas lo respeta si posible."""
    if prefer == "root" and adb_root_available(serial):
        return "root"
    if prefer == "runas" and app_is_debuggable(pkg, serial):
        return "runas"
    if prefer in (None, "auto"):
        if adb_root_available(serial):
            return "root"
        if app_is_debuggable(pkg, serial):
            return "runas"
    return "none"


def read_app_file(pkg, relpath, serial=None, mode="auto"):
    """
    Lee /data/data/<pkg>/<relpath> segun el modo. Devuelve (rc, data_bytes, err_str).
    relpath es relativo a dataDir (ej. 'shared_prefs/x.xml', 'databases/users.db').
    """
    m = get_access_mode(pkg, serial, prefer=mode)
    if m == "none":
        return 1, b"", ("Sin acceso: ni root ni run-as (app no debuggable). "
                        "Usa un emulador rooteado o repackaging (patch).")
    base = "/data/data/%s/%s" % (pkg, relpath)
    if m == "root":
        return dynadb.adb(["exec-out", "su", "-c", "cat %s" % base], serial, binary=True)
    # runas
    return dynadb.adb(["exec-out", "run-as", pkg, "cat", relpath], serial, binary=True)


def list_app_dir(pkg, subdir, serial=None, mode="auto"):
    """Lista entradas de /data/data/<pkg>/<subdir>. Devuelve (rc, lista_str, err).
    Sanea la salida de ls para no devolver mensajes de error como nombres de archivo
    (ej. 'ls:/data/...: No such file or directory' que rompe el open() en Windows)."""
    m = get_access_mode(pkg, serial, prefer=mode)
    if m == "none":
        return 1, [], "Sin acceso (none)."
    if m == "root":
        # ls -1 -> una entrada por linea (mas robusto que split sobre espacios)
        rc, out, err = dynadb.adb(["exec-out", "su", "-c",
                                   "ls -1 /data/data/%s/%s 2>/dev/null" % (pkg, subdir)], serial)
    else:
        rc, out, err = dynadb.adb(["exec-out", "run-as", pkg, "ls", "-1", subdir], serial)
    items = []
    for line in (out or "").splitlines():
        x = line.strip()
        if not x:
            continue
        # Filtrar mensajes de error de ls/BusyBox (ls: <path>: No such file...).
        # En cualquier variante, el nombre del archivo no contiene ':' salvo rars
        # ADSI (Alternate Data Streams) que no aplican en Android.
        if x.endswith(":") or x.startswith("ls:") or "No such file" in x:
            continue
        if "Permission denied" in x or "OpLe" in x:
            continue
        items.append(x)
    # Si solo habia errores, marcar rc como fallo para que el caller no intente leer
    if not items and err and ("No such file" in err or "Permission denied" in err):
        rc = 1
    return rc, items, err


def mode_label(m):
    return {"root": "root (su)", "runas": "run-as (debug)", "none": "none"}.get(m, m)