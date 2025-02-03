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
    t = b""
    for i in range((mask_len + 31) // 32):
        c = int_para_base64(i).encode()
        t += hashlib.sha3_256(seed + c).digest()
    return t[:mask_len]
    
def oaep_encode(mensagem, n, e):
    k = n.bit_length() // 8 #(k denotes the length inoctets of the RSA modulus n)
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

def os2ip(x):
    return int.from_bytes(x, byteorder='big')

def i2osp(x, x_len):
    if x >= 2**(8 * x_len):  # Se x for grande demais para caber
        raise ValueError("O número é muito grande para ser representado em x_len bytes")
    return x.to_bytes(x_len, byteorder='big')

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
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask)) #xor
    db_mask = mgf1(seed, k - l_hash_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask)) #xor

    l_hash_prime = db[:l_hash_len]

    print(l_hash_prime)
    print(l_hash)

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
assinatura_b64 = int_para_base64(assinatura)




assinaturaI2OSP = i2osp(assinatura, (n.bit_length() + 7) // 8)



with open("output.txt", 'w') as arquivo:
    arquivo.write(assinatura_b64)

print("Hash encriptado com sucesso")

if len(assinaturaI2OSP) != (n.bit_length() + 7) // 8:
    raise ValueError("Tamanho do ciphertext inválido")

oaepDecode = oaep_decode(assinaturaI2OSP, n, publicKey)



