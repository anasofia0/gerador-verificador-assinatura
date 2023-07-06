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

def OAEP_cipher(message, key, label):

    hlen = 32
    k = 256
    mlen = len(message)

    if mlen > k - hlen*2 - 2:
      raise ValueError('Message longer than expected')

    hash_l = hashlib.sha3_256(label)
    ps = int.to_bytes(0, k - mlen - 2*mlen - 2, 'big')
    aux = int.to_bytes(1, 1, 'big')
    db = hash_l + ps + aux + message
    db_mask = mgf1(seed, k-hlen-1)
    masked_db = db ^ db_mask
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = seed ^ seed_mask
    aux = int.to_bytes(0, 1, 'big')
    em = aux + maked_seed + masked_db

    ## retornar cifra rsa de em

    return em

def OAEP_decipher(e_message, key, label):
    
    hlen = 32
    k = 256

    # decifrar rsa e_message
    hash_l = hashlib.sha3_256(label)
    masked_seed = e_message[1:hlen]
    masked_db = e_message[hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = masked_seed ^ seed_mask
    db_mask = mgf1(seed, k-hlen-1)
    db = masked_db ^ db_mask
    
    hash_l1 = db[:hlen]
    found = False
    for i in range(hlen, len(db)):
        if db[i] == 1:
            found = True
            break

    message = db[i+1:]

    if hash_l1 != hash_l:
        raise ValueError("Decription hashes differ from each other")
    if e_message[0] != 0:
        raise ValueError("Encripted message does not starts with 0x00")
    if df[hlen:i] != 0:
        raise ValueError("PS is not only consists of bytes 0x00")
    if not found:
        raise ValueError("Not found bite 0x01 between PS and message")
    
    return message
