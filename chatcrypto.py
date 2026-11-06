"""
Encryption helpers for the Python chat app.

Same scheme as the browser version, so both can talk to each other:
  * password -> PBKDF2 -> (login secret, key that locks your private key)
  * ECDH P-256 key pair per user; private key stored on the server only in locked form
  * every chat uses its own AES-256-GCM key made from my private key + their public key
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CURVE = ec.SECP256R1()


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    return base64.b64decode(text)


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def derive_secrets(username, password):
    """Returns (wrap_key bytes, login secret hex). The password itself never leaves your PC."""
    bits = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), b"chatapp-v1:" + username.encode(), 600_000, 64
    )
    return bits[:32], bits[32:].hex()


def new_private_key():
    return ec.generate_private_key(CURVE)


def public_jwk(public_key):
    n = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(n.x.to_bytes(32, "big")),
        "y": b64u(n.y.to_bytes(32, "big")),
    }


def private_jwk(private_key):
    jwk = public_jwk(private_key.public_key())
    jwk["d"] = b64u(private_key.private_numbers().private_value.to_bytes(32, "big"))
    return jwk


def lock_private_key(private_key, wrap_key):
    iv = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(iv, json.dumps(private_jwk(private_key)).encode(), None)
    return json.dumps({"iv": b64(iv), "ct": b64(ct)})


def unlock_private_key(wrapped, wrap_key):
    w = json.loads(wrapped)
    jwk = json.loads(AESGCM(wrap_key).decrypt(unb64(w["iv"]), unb64(w["ct"]), None))
    return ec.derive_private_key(int.from_bytes(unb64u(jwk["d"]), "big"), CURVE)


def public_from_jwk(jwk):
    x = int.from_bytes(unb64u(jwk["x"]), "big")
    y = int.from_bytes(unb64u(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()


def chat_key(my_private_key, their_public_jwk):
    secret = my_private_key.exchange(ec.ECDH(), public_from_jwk(their_public_jwk))
    return AESGCM(secret)


def encrypt(key, text):
    iv = os.urandom(12)
    return b64(iv), b64(key.encrypt(iv, text.encode(), None))


def decrypt(key, iv, ct):
    return key.decrypt(unb64(iv), unb64(ct), None).decode()


def safety_code(my_public_jwk, their_public_jwk):
    """Both people see the same code if nobody is tampering with the keys."""
    f = lambda j: j["x"] + "." + j["y"]
    joined = "|".join(sorted([f(my_public_jwk), f(their_public_jwk)]))
    h = hashlib.sha256(joined.encode()).hexdigest()[:24].upper()
    return " ".join(h[i:i + 4] for i in range(0, 24, 4))
