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

def int_para_base64(numero):
    numero_bytes = numero.to_bytes((numero.bit_length() + 7) // 8, byteorder='big')
    numero_base64 = base64.b64encode(numero_bytes).decode('utf-8')
    return numero_base64

def base64_para_int(base64_str):
    numero_bytes = base64.b64decode(base64_str)
    return int.from_bytes(numero_bytes, byteorder='big')

# 1. Carregar mensagem e chaves
message = ler_arquivo("message").encode('utf-8')
n = int(ler_arquivo('N'))
privateKey = int(ler_arquivo('privateKey'))

# 2. Calcular hash SHA3-256
hash_sha3_256 = hashlib.sha3_256(message).digest()

# 3. Converter hash para inteiro
hash_int = int(hash_sha3_256.hex(),16)

# 4. Aplicar assinatura RSA: S = (hash^d) mod n
assinatura = pow(hash_int, privateKey, n)

# 5. Codificar resultado em Base64
assinatura_b64 = int_para_base64(assinatura)

with open("output.txt", 'w') as arquivo:
    arquivo.write(assinatura_b64)

print("Hash encriptado com sucesso")