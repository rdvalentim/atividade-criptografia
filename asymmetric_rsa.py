# asymmetric_rsa.py
import argparse
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys(private_path="private.pem", public_path="public.pem", bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Chaves salvas: {private_path}, {public_path}")

def _load_public(path="public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def _load_private(path="private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_with_public(plaintext: str, public_path="public.pem") -> str:
    pub = _load_public(public_path)
    ct = pub.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(ct).decode("utf-8")

def decrypt_with_private(b64: str, private_path="private.pem") -> str:
    priv = _load_private(private_path)
    ct = base64.b64decode(b64)
    pt = priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return pt.decode("utf-8")

def main():
    parser = argparse.ArgumentParser(description="RSA-OAEP (Assimétrico)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkeys", help="Gerar par de chaves")
    p_gen.add_argument("--bits", type=int, default=2048)

    p_enc = sub.add_parser("encrypt", help="Cifrar com a chave pública")
    p_enc.add_argument("--public", default="public.pem")
    p_enc.add_argument("--text", required=True)

    p_dec = sub.add_parser("decrypt", help="Decifrar com a privada")
    p_dec.add_argument("--private", default="private.pem")
    p_dec.add_argument("--b64", required=True)

    args = parser.parse_args()
    if args.cmd == "genkeys":
        generate_keys(bits=args.bits)
    elif args.cmd == "encrypt":
        print(encrypt_with_public(args.text, args.public))
    else:
        print(decrypt_with_private(args.b64, args.private))

if __name__ == "__main__":
    main()