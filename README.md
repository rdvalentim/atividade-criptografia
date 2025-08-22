# Trabalho: Criptografia com Chave Simétrica e Assimétrica

Este repositório contém:
- **AES-GCM** (simétrico) com derivação via PBKDF2.
- **RSA-OAEP** (assimétrico) para geração de chaves, cifra e decifra.
- **gui_crypto.py** é um conjunto das duas ferramentas acima porém com uma interface gráfica.

## Como usar

```bash
pip install -r requirements.txt

# Simétrico (AES-GCM)
python symmetric_aes_gcm.py encrypt --password "SenhaForte" --text "mensagem"
python symmetric_aes_gcm.py decrypt --password "SenhaForte" --b64 "<base64>"

# Assimétrico (RSA-OAEP)
python asymmetric_rsa.py genkeys --bits 2048
python asymmetric_rsa.py encrypt --public public.pem --text "segredo"
python asymmetric_rsa.py decrypt --private private.pem --b64 "<base64>"

# Interface visual
python gui_crypto.py