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

message = ler_arquivo("message").encode('utf-8')
hash_sha3_256 = hashlib.sha3_256(message).digest()
hash_base64 = base64.b64encode(hash_sha3_256).decode('utf-8') # Convertendo o hash para base64

# Lendo o hash encriptado e as chaves
hash = ler_arquivo("output").encode('utf-8')
assinatura_int = base64_para_int(hash)
n = int(ler_arquivo('N'))
publicKey = int(ler_arquivo('publicKey'))
hash_decifrado_int = pow(assinatura_int, publicKey, n)
decrypt = int_para_base64(hash_decifrado_int)
if decrypt == hash_base64:
    print("Hashes iguais")
else:
    print("Hashes diferentes")