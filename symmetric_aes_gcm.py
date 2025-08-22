# symmetric_aes_gcm.py
import os
import base64
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Parâmetros de derivação
KDF_ITER = 200_000
KEY_LEN  = 32          # AES-256
SALT_LEN = 16
NONCE_LEN = 12         # recomendado para GCM

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITER,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt(plaintext: str, password: str, aad: str = "") -> str:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))

    # No AESGCM.encrypt, ct = ciphertext || tag
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("utf-8")

def decrypt(b64: str, password: str, aad: str = "") -> str:
    blob = base64.b64decode(b64)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    ct = blob[SALT_LEN+NONCE_LEN:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad.encode("utf-8"))
    return pt.decode("utf-8")

def main():
    parser = argparse.ArgumentParser(description="AES-GCM (Simétrico) com senha")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Cifrar texto")
    p_enc.add_argument("--password", required=True)
    p_enc.add_argument("--aad", default="", help="Associated data (opcional)")
    p_enc.add_argument("--text", required=True)

    p_dec = sub.add_parser("decrypt", help="Decifrar texto Base64")
    p_dec.add_argument("--password", required=True)
    p_dec.add_argument("--aad", default="", help="Associated data (opcional)")
    p_dec.add_argument("--b64", required=True)

    args = parser.parse_args()
    if args.cmd == "encrypt":
        print(encrypt(args.text, args.password, args.aad))
    else:
        print(decrypt(args.b64, args.password, args.aad))

if __name__ == "__main__":
    main()