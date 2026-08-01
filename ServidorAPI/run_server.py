#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_server.py - Arranque del servidor mock de Banco Alien (MASVS-NETWORK).

Un solo comando lo deja todo listo:
  - crea el entorno virtual (.venv)
  - instala Flask + cryptography
  - genera el certificado self-signed (la primera vez)
  - levanta el servidor: HTTP (cleartext) en :8000 y HTTPS (pinned) en :8443

Uso:
    python run_server.py
"""
import os
import sys
import subprocess
import venv

BASE = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(BASE, ".venv")
DEPS = ["flask", "cryptography"]


def venv_python():
    return (os.path.join(VENV, "Scripts", "python.exe") if os.name == "nt"
            else os.path.join(VENV, "bin", "python"))


def ensure_env():
    if not os.path.exists(venv_python()):
        print("[i] Creando entorno virtual (.venv) ...")
        venv.EnvBuilder(with_pip=True).create(VENV)
    # ¿ya están las dependencias?
    try:
        subprocess.check_call([venv_python(), "-c", "import flask, cryptography"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("[i] Instalando dependencias (Flask, cryptography) ...")
        subprocess.check_call([venv_python(), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        subprocess.check_call([venv_python(), "-m", "pip", "install", "--quiet"] + DEPS)
        print("[i] Dependencias instaladas.")


def main():
    ensure_env()
    print("[i] Iniciando servidor mock ...\n")
    rc = subprocess.call([venv_python(), os.path.join(BASE, "mock_api.py")])
    sys.exit(rc)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Servidor detenido.")
