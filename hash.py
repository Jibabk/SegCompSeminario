import base64
import hashlib
import os

def ler_arquivo(caminho_arquivo):
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
            conteudo = arquivo.read()
        return conteudo
    except FileNotFoundError:
        return "Arquivo não encontrado."
    except Exception as e:
        return f"Ocorreu um erro: {e}".encode('utf-8')

def mgf1(seed, mask_len):
    """Mask Generation Function 1 (MGF1)"""
    h_len = hashlib.sha3_256().digest_size
    counter = 0
    output = b""
    
    while len(output) < mask_len:
        c = counter.to_bytes(4, byteorder='big')  # FIX
        output += hashlib.sha3_256(seed + c).digest()
        counter += 1

    return output[:mask_len]
    
def oaep_encode(mensagem, n, e):
    k = (n.bit_length() + 7) // 8 #(k denotes the length inoctets of the RSA modulus n)
    if len(mensagem) > k - 2 * hashlib.sha3_256().digest_size - 2: # mLen > k - 2hLen - 2
        raise ValueError("Mensagem muito longa")
    
    l_hash = hashlib.sha3_256(b"").digest()
    l_hash_len = len(l_hash)

    #zero octets padding
    ps = b"\x00" * (k - len(mensagem) - 2 * l_hash_len - 2)

    #Concatenate
    db = l_hash + ps + b"\x01" + mensagem

    # Generate a random octet string seed of length hLen
    seed = os.urandom(l_hash_len)

    #mask generation function
    db_mask = mgf1(seed, k - l_hash_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask)) #xor
    seed_mask = mgf1(masked_db, l_hash_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask)) #xor

    return b"\x00" + masked_seed + masked_db

def os2ip(x: bytes) -> int:
    return int.from_bytes(x, byteorder='big')

def i2osp(x: int, xlen: int) -> bytes:
    return x.to_bytes(xlen, byteorder='big')

def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

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
publicKey = int(ler_arquivo('publicKey'))

# 2. Calcular hash SHA3-256
hash_sha3_256 = hashlib.sha3_256(message).digest()

# 3. Converter hash para inteiro
hash_int = int(hash_sha3_256.hex(),16)

oaepEncode = oaep_encode(hash_sha3_256, n, privateKey)


oaepEncode_int = os2ip(oaepEncode)



# 4. Aplicar assinatura RSA: S = (hash^d) mod n
assinatura = pow(oaepEncode_int, privateKey, n)


# 5. Codificar resultado em Base64
assinaturaI2OSP = i2osp(assinatura, (n.bit_length() + 7) // 8)


assinatura_b64 = base64.b64encode(assinaturaI2OSP).decode('utf-8')



with open("output.txt", 'w') as arquivo:
    arquivo.write(assinatura_b64)

print("Hash encriptado com sucesso")





