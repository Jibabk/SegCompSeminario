import base64
import hashlib

def ler_arquivo(caminho_arquivo):
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
            conteudo = arquivo.read()
        return conteudo
    except FileNotFoundError:
        return "Arquivo não encontrado."
    except Exception as e:
        return f"Ocorreu um erro: {e}".encode('utf-8')

str = "message"

enconded = ler_arquivo(str).encode('utf-8')
print(ler_arquivo(str))
print(enconded)

# Gerando o hash SHA-256
hash_sha256 = hashlib.sha256(enconded).digest()

# Convertendo o hash para Base64
hash_base64 = base64.b64encode(hash_sha256).decode('utf-8')

print(hash_base64)