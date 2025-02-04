import math
from random import randint
import random
import secrets
from sympy import nextprime


def miller_rabin(n, k):
    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def getPrime():
    while True:
        print("Calculando primo...")
        prime = secrets.randbits(1024)
        if miller_rabin(prime, 40):
            return prime

def getPublicKey(prime, prime2):
    pi_n = (prime-1)*(prime2-1)
    while True:
        print("Calculando chave pública...")
        publicKey = randint(2, pi_n-1)
        if math.gcd(publicKey, pi_n) == 1:
            return publicKey

def getPrivateKey(publicKey, prime, prime2):
    phi = (prime-1)*(prime2-1)
    return pow(publicKey, -1, phi)


prime= getPrime()
prime2= nextprime(prime)

publicKey = getPublicKey(prime, prime2)
privateKey = getPrivateKey(publicKey, prime, prime2)
    
with open('publicKey', 'w') as arquivo:
    arquivo.write(str(publicKey))

with open('privateKey', 'w') as arquivo:
    arquivo.write(str(privateKey))

with open('N', 'w') as arquivo:
    arquivo.write(str(prime*prime2))
