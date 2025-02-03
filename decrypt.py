import base64
import hashlib
import os
from math import ceil


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

def oaep_decode(c, n, d):
    k = (n.bit_length() + 7) // 8
    
    if k < 2 * hashlib.sha3_256().digest_size + 2:
        raise ValueError("Decodificação falhou")

    
    c_int = os2ip(c)

    if c_int >= n:
        raise ValueError("Decodificação falhou")

    m_int = pow(c_int, d, n)


    m = i2osp(m_int, k)

    l_hash = hashlib.sha3_256(b"").digest()
    l_hash_len = len(l_hash)


    masked_seed = m[1:l_hash_len + 1]


    masked_db = m[l_hash_len + 1:]
    

    seed_mask = mgf1(masked_db, l_hash_len)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - l_hash_len - 1)
    db = xor(masked_db, db_mask)

    l_hash_prime = db[:l_hash_len]

    

    if l_hash_prime != l_hash:
       raise ValueError("Decodificação falhou")
    i = l_hash_len
    while i < len(db):
        if db[i] == 1:
            i += 1
            break
        elif db[i] != 0:
            raise ValueError("Decodificação falhou")
        i += 1
    return db[i:]

def int_para_base64(numero):
    numero_bytes = numero.to_bytes((numero.bit_length() + 7) // 8, byteorder='big')
    numero_base64 = base64.b64encode(numero_bytes).decode('utf-8')
    return numero_base64

def base64_para_int(base64_str):
    numero_bytes = base64.b64decode(base64_str)
    return int.from_bytes(numero_bytes, byteorder='big')

def base64_para_bytes(base64_str):
    return base64.b64decode(base64_str)

message = ler_arquivo("message").encode('utf-8')
hash_sha3_256 = hashlib.sha3_256(message).digest()


# Lendo o hash encriptado e as chaves
oaepEncoded64 = ler_arquivo("output.txt").encode('utf-8')
oaepEncoded = base64_para_bytes(oaepEncoded64)

n = int(ler_arquivo('N'))
publicKey = int(ler_arquivo('publicKey'))

oaepDecoded = oaep_decode(oaepEncoded, n, publicKey)

print("Hash original:   ", hash_sha3_256)

print("Hash decriptado: ", oaepDecoded)

if oaepDecoded == hash_sha3_256:
    print("Hashes iguais")
else:
    print("Hashes diferentes")