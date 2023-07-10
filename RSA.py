import hashlib


def xor_bytes(a, b):
    return bytes(c ^ d for c, d in zip(a, b))

def RSA(message, key):

    k = key[0].bit_length() // 8
    message = int.from_bytes(message, 'big')
    message = pow(message, key[1], key[0])
    return message.to_bytes(k, 'big')

def mgf1(seed, length, hash_func=hashlib.sha3_256):

    count = 0
    output = b''

    while len(output) < length:
        C = int.to_bytes(count, 4, 'big')
        output += hash_func(seed + C).digest()
        count += 1

    return output[:length]

def OAEP_cipher(message, key, label, seed):

    message = bytes(message, 'utf-8')
    seed = seed.to_bytes(32, 'big')

    hlen = 32
    k = 256
    mlen = len(message)

    hash_l = hashlib.sha3_256(label).digest()
    ps = int.to_bytes(0, k - mlen - 2*mlen - 2, 'big')
    aux = int.to_bytes(1, 1, 'big')
    db = hash_l + ps + aux + message
    db_mask = mgf1(seed, k-hlen-1)
    masked_db = xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor_bytes(seed, seed_mask)
    aux = int.to_bytes(0, 1, 'big')
    em = aux + masked_seed + masked_db

    em = RSA(em, key)

    return em

def OAEP_decipher(e_message, key, label):

    hlen = 32
    k = 256

    e_message = RSA(e_message, key)

    print(e_message)

    hash_l = hashlib.sha3_256(label).digest()
    masked_seed = e_message[1:hlen]
    masked_db = e_message[hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k-hlen-1)
    db = xor_bytes(masked_db, db_mask)
    
    hash_l1 = db[:hlen]

    print(db)

    message = db.split(b'\x01')[-1]

    return message
