import math
from random import randint

def getPrimes():
    prime = 626102482611964823574740297655240383896103409126305443231664437300671343473331142928477411038355500769069913097297412351005814654343771608169029687424236812322621038417933988549672416519747357810576844756456600250346780519085672322878979563949243588898853840222535853668582616930321446822313580573101
    prime2 = 272335316914061944344791242168215509832038597873032357792288827818668168095620264348197396448363692802184796186915779390493453083152197991015059537655151496011916744633214075484188775791085933302125690681641428998202992001236479801624706752643396684844435165441927534373879845504706298181014950909757
    return prime, prime2

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


prime, prime2 = getPrimes()
publicKey = getPublicKey(prime, prime2)
privateKey = getPrivateKey(publicKey, prime, prime2)
    
with open('publicKey', 'w') as arquivo:
    arquivo.write(str(publicKey))

with open('privateKey', 'w') as arquivo:
    arquivo.write(str(privateKey))

with open('N', 'w') as arquivo:
    arquivo.write(str(prime*prime2))
