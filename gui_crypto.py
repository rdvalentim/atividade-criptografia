# gui_crypto.py
# GUI simples (Tkinter) para cifrar/decifrar com AES-GCM (simétrico) e RSA-OAEP (assimétrico)
# Dependência: cryptography
# Instalar: pip install cryptography

import base64
import itertools
import os
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ====== Criptografia moderna (AES-GCM, RSA-OAEP) usando 'cryptography' ======
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    CRYPTO_OK = True
except Exception as e:
    CRYPTO_OK = False

# ---------- AES-GCM (simétrico)
KDF_ITER = 200_000
KEY_LEN = 32      # AES-256
SALT_LEN = 16
NONCE_LEN = 12    # recomendado p/ GCM


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITER,
    )
    return kdf.derive(password.encode('utf-8'))


def aes_gcm_encrypt(plaintext: str, password: str, aad: str = "") -> str:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad.encode('utf-8'))
    blob = salt + nonce + ct  # ct já inclui a tag GCM ao final
    return base64.b64encode(blob).decode('utf-8')


def aes_gcm_decrypt(b64: str, password: str, aad: str = "") -> str:
    blob = base64.b64decode(b64)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    ct = blob[SALT_LEN+NONCE_LEN:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad.encode('utf-8'))
    return pt.decode('utf-8')


# ---------- RSA-OAEP (assimétrico)

def rsa_generate(bits: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    pem_priv = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pem_pub = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_priv.decode('utf-8'), pem_pub.decode('utf-8')


def rsa_encrypt_with_public(plaintext: str, public_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_pem.encode('utf-8'))
    ct = pub.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode('utf-8')


def rsa_decrypt_with_private(b64: str, private_pem: str) -> str:
    priv = serialization.load_pem_private_key(private_pem.encode('utf-8'), password=None)
    ct = base64.b64decode(b64)
    pt = priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return pt.decode('utf-8')


# ====== GUI (Tkinter) ======
class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptografia: AES-GCM / RSA-OAEP / Vigenère")
        self.geometry("980x680")
        self.minsize(900, 600)

        if not CRYPTO_OK:
            messagebox.showwarning(
                "Dependência ausente",
                "O pacote 'cryptography' não foi encontrado.\n\nInstale com:\n    pip install cryptography"
            )

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        # Abas
        self.tab_aes = ttk.Frame(nb)
        self.tab_rsa = ttk.Frame(nb)
        self.tab_vig = ttk.Frame(nb)

        nb.add(self.tab_aes, text="AES-GCM (Simétrico)")
        nb.add(self.tab_rsa, text="RSA-OAEP (Assimétrico)")

        self._build_tab_aes()
        self._build_tab_rsa()

    # ---------- Helpers UI ----------
    def _text_area(self, parent):
        txt = tk.Text(parent, height=6, wrap='word')
        txt.configure(font=('Menlo', 11))
        return txt

    def _label(self, parent, text):
        return ttk.Label(parent, text=text)

    def _row(self, parent):
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, padx=8, pady=6)
        return row

    def _btn_copy(self, widget_getter):
        def _copy():
            self.clipboard_clear()
            self.clipboard_append(widget_getter())
            messagebox.showinfo("Copiado", "Conteúdo copiado para a área de transferência.")
        return ttk.Button(self, text="Copiar", command=_copy)

    def _load_file_into(self, text_widget: tk.Text):
        path = filedialog.askopenfilename(title="Abrir arquivo")
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            text_widget.delete('1.0', tk.END)
            text_widget.insert('1.0', content)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar arquivo:\n{e}")

    def _save_text_from(self, text_widget: tk.Text, default_name: str):
        path = filedialog.asksaveasfilename(title="Salvar como", initialfile=default_name)
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text_widget.get('1.0', tk.END).strip())
            messagebox.showinfo("Salvo", f"Arquivo salvo em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar arquivo:\n{e}")

    # ---------- Aba AES ----------
    def _build_tab_aes(self):
        frm = self.tab_aes

        r = self._row(frm)
        self._label(r, "Senha (chave)").pack(side=tk.LEFT)
        self.ent_aes_pwd = ttk.Entry(r, show='*', width=40)
        self.ent_aes_pwd.pack(side=tk.LEFT, padx=8)

        r = self._row(frm)
        self._label(r, "AAD (dados associados, opcional)").pack(side=tk.LEFT)
        self.ent_aes_aad = ttk.Entry(r, width=50)
        self.ent_aes_aad.pack(side=tk.LEFT, padx=8)

        # Entrada de texto
        r = self._row(frm)
        self._label(r, "Texto claro").pack(anchor='w')
        self.txt_aes_plain = self._text_area(frm)
        self.txt_aes_plain.pack(fill=tk.BOTH, expand=True, padx=8)

        # Saída base64
        r = self._row(frm)
        self._label(r, "Saída Base64 (cifra)").pack(anchor='w')
        self.txt_aes_b64 = self._text_area(frm)
        self.txt_aes_b64.pack(fill=tk.BOTH, expand=True, padx=8)

        # Botões
        row_btn = self._row(frm)
        ttk.Button(row_btn, text="Cifrar", command=self._aes_do_encrypt).pack(side=tk.LEFT)
        ttk.Button(row_btn, text="Decifrar", command=self._aes_do_decrypt).pack(side=tk.LEFT, padx=8)
        ttk.Button(row_btn, text="Copiar Base64", command=lambda: self._copy_from(self.txt_aes_b64)).pack(side=tk.LEFT, padx=8)
        ttk.Button(row_btn, text="Limpar", command=self._aes_clear).pack(side=tk.LEFT)

    def _copy_from(self, text_widget: tk.Text):
        self.clipboard_clear()
        self.clipboard_append(text_widget.get('1.0', tk.END).strip())
        messagebox.showinfo("Copiado", "Conteúdo copiado para a área de transferência.")

    def _aes_do_encrypt(self):
        try:
            pwd = self.ent_aes_pwd.get().strip()
            if not pwd:
                messagebox.showwarning("Atenção", "Informe uma senha.")
                return
            aad = self.ent_aes_aad.get().strip()
            pt = self.txt_aes_plain.get('1.0', tk.END).strip()
            b64 = aes_gcm_encrypt(pt, pwd, aad)
            self.txt_aes_b64.delete('1.0', tk.END)
            self.txt_aes_b64.insert('1.0', b64)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao cifrar (AES-GCM):\n{e}")

    def _aes_do_decrypt(self):
        try:
            pwd = self.ent_aes_pwd.get().strip()
            if not pwd:
                messagebox.showwarning("Atenção", "Informe uma senha.")
                return
            aad = self.ent_aes_aad.get().strip()
            b64 = self.txt_aes_b64.get('1.0', tk.END).strip()
            pt = aes_gcm_decrypt(b64, pwd, aad)
            self.txt_aes_plain.delete('1.0', tk.END)
            self.txt_aes_plain.insert('1.0', pt)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao decifrar (AES-GCM):\n{e}")

    def _aes_clear(self):
        self.ent_aes_pwd.delete(0, tk.END)
        self.ent_aes_aad.delete(0, tk.END)
        self.txt_aes_plain.delete('1.0', tk.END)
        self.txt_aes_b64.delete('1.0', tk.END)

    # ---------- Aba RSA ----------
    def _build_tab_rsa(self):
        frm = self.tab_rsa

        # geração de chaves
        box_keys = ttk.LabelFrame(frm, text="Chaves (PEM)")
        box_keys.pack(fill=tk.BOTH, expand=False, padx=8, pady=8)

        row = self._row(box_keys)
        ttk.Button(row, text="Gerar par de chaves (2048)", command=self._rsa_gen_keys).pack(side=tk.LEFT)
        ttk.Button(row, text="Salvar privada…", command=lambda: self._save_text_from(self.txt_rsa_priv, 'private.pem')).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Salvar pública…", command=lambda: self._save_text_from(self.txt_rsa_pub, 'public.pem')).pack(side=tk.LEFT)

        row = self._row(box_keys)
        self._label(row, "Chave privada (PEM)").pack(anchor='w')
        self.txt_rsa_priv = self._text_area(box_keys)
        self.txt_rsa_priv.pack(fill=tk.BOTH, expand=True, padx=8)

        row = self._row(box_keys)
        self._label(row, "Chave pública (PEM)").pack(anchor='w')
        self.txt_rsa_pub = self._text_area(box_keys)
        self.txt_rsa_pub.pack(fill=tk.BOTH, expand=True, padx=8)

        # cifra/decifra
        box_ops = ttk.LabelFrame(frm, text="Operações")
        box_ops.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        row = self._row(box_ops)
        self._label(row, "Texto claro").pack(anchor='w')
        self.txt_rsa_plain = self._text_area(box_ops)
        self.txt_rsa_plain.pack(fill=tk.BOTH, expand=True, padx=8)

        row = self._row(box_ops)
        self._label(row, "Cifra (Base64)").pack(anchor='w')
        self.txt_rsa_b64 = self._text_area(box_ops)
        self.txt_rsa_b64.pack(fill=tk.BOTH, expand=True, padx=8)

        row_btn = self._row(box_ops)
        ttk.Button(row_btn, text="Cifrar com pública", command=self._rsa_encrypt).pack(side=tk.LEFT)
        ttk.Button(row_btn, text="Decifrar com privada", command=self._rsa_decrypt).pack(side=tk.LEFT, padx=8)
        ttk.Button(row_btn, text="Carregar privada de arquivo…", command=lambda: self._load_file_into(self.txt_rsa_priv)).pack(side=tk.LEFT, padx=8)
        ttk.Button(row_btn, text="Carregar pública de arquivo…", command=lambda: self._load_file_into(self.txt_rsa_pub)).pack(side=tk.LEFT)
        ttk.Button(row_btn, text="Limpar tudo", command=self._rsa_clear).pack(side=tk.LEFT, padx=8)

        hint = ttk.Label(frm, foreground='#444', wraplength=900,
                         text="Dica: RSA é ideal para mensagens curtas. Em produção usa-se esquema híbrido (AES para o texto e RSA para a chave AES).")
        hint.pack(anchor='w', padx=12, pady=(0, 8))

    def _rsa_gen_keys(self):
        try:
            pem_priv, pem_pub = rsa_generate(2048)
            self.txt_rsa_priv.delete('1.0', tk.END)
            self.txt_rsa_priv.insert('1.0', pem_priv)
            self.txt_rsa_pub.delete('1.0', tk.END)
            self.txt_rsa_pub.insert('1.0', pem_pub)
            messagebox.showinfo("OK", "Par de chaves gerado na interface. Salve-as em arquivos .pem.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao gerar chaves RSA:\n{e}")

    def _rsa_encrypt(self):
        try:
            pub_pem = self.txt_rsa_pub.get('1.0', tk.END).strip()
            if not pub_pem:
                messagebox.showwarning("Atenção", "Informe/Carregue a chave pública (PEM).")
                return
            pt = self.txt_rsa_plain.get('1.0', tk.END).strip()
            b64 = rsa_encrypt_with_public(pt, pub_pem)
            self.txt_rsa_b64.delete('1.0', tk.END)
            self.txt_rsa_b64.insert('1.0', b64)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao cifrar (RSA-OAEP):\n{e}")

    def _rsa_decrypt(self):
        try:
            priv_pem = self.txt_rsa_priv.get('1.0', tk.END).strip()
            if not priv_pem:
                messagebox.showwarning("Atenção", "Informe/Carregue a chave privada (PEM).")
                return
            b64 = self.txt_rsa_b64.get('1.0', tk.END).strip()
            pt = rsa_decrypt_with_private(b64, priv_pem)
            self.txt_rsa_plain.delete('1.0', tk.END)
            self.txt_rsa_plain.insert('1.0', pt)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao decifrar (RSA-OAEP):\n{e}")

    def _rsa_clear(self):
        self.txt_rsa_priv.delete('1.0', tk.END)
        self.txt_rsa_pub.delete('1.0', tk.END)
        self.txt_rsa_plain.delete('1.0', tk.END)
        self.txt_rsa_b64.delete('1.0', tk.END)


if __name__ == '__main__':
    app = CryptoGUI()
    app.mainloop()
