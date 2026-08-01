# -*- coding: utf-8 -*-
"""
mock_api.py - API simulada para el módulo de RED de Banco Alien (MASVS-NETWORK).

- HTTP en claro  (:8000)  /promo         -> flag "cleartext" (se captura sin pinning)
- HTTPS pinned   (:8443)  /secure/vault  -> flag "pinning"   (requiere Frida ssl_unpin)

La primera vez genera un certificado self-signed (server.crt / server.key) e imprime
el PIN de la clave pública para pegarlo en la app. No necesita openssl.
"""
import os
import ssl
import base64
import hashlib
import socket
import ipaddress
import datetime
import threading

from flask import Flask, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE = os.path.dirname(os.path.abspath(__file__))
CRT = os.path.join(BASE, "server.crt")
KEY = os.path.join(BASE, "server.key")

# --- Flags que viajan en la respuesta (NO van dentro del APK) ---
FLAG_HTTP = "ALIEN{cl34rt3xt_4p1}"
FLAG_HTTPS = "ALIEN{ssl_p1nn1ng_0ff}"

app = Flask(__name__)


def lan_ip():
    """IP LAN del host (la que el emulador Genymotion usa para alcanzar tu PC)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ensure_cert():
    """Genera el cert self-signed la primera vez, con SAN para localhost, 10.0.2.2 y la IP LAN."""
    if os.path.exists(CRT) and os.path.exists(KEY):
        return
    ip = lan_ip()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"BancoAlien Mock API")])
    sans = [x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address(u"10.0.2.2"))]
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(str(ip))))
    except Exception:
        pass
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(CRT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def spki_pin():
    """PIN sha256 de la SubjectPublicKeyInfo (lo que espera OkHttp CertificatePinner)."""
    with open(CRT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


@app.get("/")
def home():
    return jsonify({"service": "Banco Alien Mock API",
                    "endpoints": ["/promo  (HTTP claro)", "/secure/vault  (HTTPS pinned)"]})


@app.get("/promo")                       # HTTP en claro -> flag cleartext
def promo():
    return jsonify({"promo": "Banca intergalactica 0% comisiones", "flag": FLAG_HTTP})


@app.get("/secure/vault")                # HTTPS pinned -> flag pinning
def vault():
    return jsonify({"vault": "saldo-consolidado", "flag": FLAG_HTTPS})


# Puertos NO comunes (evitan choques con otros servicios del alumno)
PORT_HTTP = 8888
PORT_HTTPS = 9443


def run_http():
    app.run(host="0.0.0.0", port=PORT_HTTP, threaded=True)


def main():
    ensure_cert()
    ip = lan_ip()
    pin = spki_pin()
    line = "=" * 66
    print(line)
    print("  ALIEN-BANK  -  Servidor mock (MASVS-NETWORK)")
    print(line)
    print("  HTTP  (cleartext):  http://%s:%d/promo" % (ip, PORT_HTTP))
    print("  HTTPS (pinned):     https://%s:%d/secure/vault" % (ip, PORT_HTTPS))
    print()
    print("  Como lo alcanza el emulador:")
    print("    - AVD (Android Studio):  10.0.2.2   (por defecto, no cambies nada)")
    print("    - Genymotion:            10.0.3.2")
    print("    - Dispositivo/otro PC:   %s   (IP LAN de esta maquina)" % ip)
    print()
    print("  En la app: abre Ajustes -> campo 'Servidor' y escribe la IP de arriba.")
    print("  Los puertos (%d/%d) y el PIN ya van fijos en la APK; NO recompilar." % (PORT_HTTP, PORT_HTTPS))
    print()
    print("  PIN de este certificado (ya horneado en la app):")
    print("     VAULT_PIN = \"%s\"" % pin)
    print()
    print("  IMPORTANTE: reparte server.crt + server.key junto a este script para")
    print("  que TODOS compartan el mismo PIN. Certificado fijo (validez 10 anios).")
    print("  Ctrl+C para detener.")
    print(line)
    # HTTP en un hilo; HTTPS en el principal
    threading.Thread(target=run_http, daemon=True).start()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CRT, KEY)
    app.run(host="0.0.0.0", port=PORT_HTTPS, ssl_context=ctx, threaded=True)


if __name__ == "__main__":
    main()
