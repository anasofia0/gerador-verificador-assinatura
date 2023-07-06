import random 

def miller_rabin(n, k):

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in xrange(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in xrange(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_keys(k=2):

    keys = []
    
    for i in range(k):
        found = False
        p = random.getrandbits(1024)
        while not found:        
            if miller_rabin(p, 40) and p not in keys:
                found = True
                keys.append(p)
            else:
                p = random.getrandbits(1024)

    return keys
