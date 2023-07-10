import random
import math
import secrets
import sys
sys.setrecursionlimit(1500)

def miller_rabin(n, k):

    if n == 2 or n == 3:
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

def generate_keys(k=2, key_length=1024):

    keys = []
    
    for _ in range(k):
        found = False
        p = secrets.randbits(key_length)
        while not found:        
            if miller_rabin(p, 40) and p not in keys:
                found = True
                keys.append(p)
            else:
                p = secrets.randbits(key_length)

    return keys

def generate_e(max_value):
    while True:
        n = secrets.randbelow(max_value)
        if math.gcd(max_value, n) == 1:
            return n

def generate_d(e, max_value):
    return modular_inversion(e, max_value)[1] % max_value

def modular_inversion(e, max_value):
    if e == 0:
        return (max_value, 0, 1)
    else:
        a, b, c = modular_inversion(max_value % e, e)
        return (a, c - (max_value // e) * b, b)

def generate_pub_priv_keys(p, q):
    
    n = p*q
    phi = (p-1)*(q-1)

    e = generate_e(phi)
    d = generate_d(e, phi)

    if d < 0:
        d += phi

    public_key = (n, e)
    private_key = (n, d)

    return (public_key, private_key)
