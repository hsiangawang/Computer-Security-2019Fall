# Some of the code was referenced from https://facthacks.cr.yp.to/index.html

import gmpy2
from fractions import gcd
from Crypto.PublicKey import RSA
from pbp import decrypt

def prod(X):
    result = 1
    for x in X:
        result *= x
    return result

def product(X):
    if len(X) == 0: return 1
    while len(X) > 1:
        X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
    return X[0]

def producttree(X):
    result = [X]
    while len(X) > 1:
        X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
        result.append(X)
    return result

def remaindersusingproducttree(n, T):
    result = [n]
    for t in reversed(T):
        result = [result[i/2] % t[i] for i in range(len(t))]
    return result

def remainders(n, X):
    return remaindersusingproducttree(n, producttree(X))

def batchgcd(X):
    R = remainders(product(X),[n ** 2 for n in X])
    return [gcd(r/n,n) for r,n in zip(R,X)]

with open('moduli.hex') as f:
    lines = f.readlines()
    lines = [line.strip() for line in lines]
    moduli = [int(line, 16) for line in lines]

gcds = batchgcd(moduli)

with open('3.2.4_ciphertext.enc.asc') as f:
    encrypted = f.read()

e = 65537L
for gcd, modulu in zip(gcds, moduli):
    if gcd == 1:
        continue
    p = gcd
    q = modulu / p
    d = gmpy2.invert(e, (p - 1) * (q - 1))
    
    key = RSA.construct((modulu, e, long(d)))
    try:
        decrypted = decrypt(key, encrypted)
        print(decrypted)
    except ValueError:
        continue