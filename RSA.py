import hashlib

#hashlib.sha3_224()

def mgf1(seed, length, hash_func=hashlib.sha3_256):

    count = 0
    output = b''

    while len(output) < length:
        C = int.to_bytes(count, 4, 'big')
        output += hash_func(seed + C).digest
        count += 1

    return output[:length]

def OAEP_cipher(message, key):

    hlen = 32
    k = 256

def OAEP_decipher():
    pass

