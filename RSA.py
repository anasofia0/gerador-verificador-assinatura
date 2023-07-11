import hashlib

# realiza o xor de elemento por elemento entre dois objetos bytes
def xor_bytes(a, b):
    return bytes(c ^ d for c, d in zip(a, b))

# cifração e decifração RSA
def RSA(message, EorD, n):
    return pow(message, EorD, n)

# Mask Generation Function
def mgf1(seed, length, hash_func=hashlib.sha3_256):

    count = 0
    output = b''

    while len(output) < length:
        C = int.to_bytes(count, 4, 'big')
        output += hash_func(seed + C).digest()
        count += 1

    return output[:length]

# cifra com OAEP e depois RSA
def OAEP_cipher(message, key, label, seed):

    seed = seed.to_bytes(32, 'big') # convertendo seed to bytes

    hlen = 32
    mlen = len(message)
    k = key[0].bit_length() // 8

    hash_l = hashlib.sha3_256(label).digest()
    ps = int.to_bytes(0, k - mlen - 2*hlen - 2, 'big')
    db = hash_l + ps + b'\x01' + message
    db_mask = mgf1(seed, k-hlen-1)
    masked_db = xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor_bytes(seed, seed_mask)
    em = b'\x00' + masked_seed + masked_db

    em = RSA(int.from_bytes(em, 'big'), key[1], key[0]) # cifrando resultado de OAEP com RSA

    return em

# decifra com RSA e depois OAEP
def OAEP_decipher(e_message, key, label):

    hlen = 32
    k = key[0].bit_length() // 8

    e_message = RSA(e_message, key[1], key[0]).to_bytes(k, 'big') # decifrando para obter cifra OAEP

    masked_seed = e_message[1:hlen+1]
    masked_db = e_message[-(k-hlen-1):]

    seed_mask = mgf1(masked_db, hlen)
    seed = xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k-hlen-1)
    db = xor_bytes(masked_db, db_mask)
    
    message_padding = db[hlen:]

    found = False
    for i in range(len(message_padding)): # achando mensagem
      if message_padding[i] == 1:
        found = True
        break
      
    message = message_padding[i+1:] # obtendo mensagem

    hash_l = hashlib.sha3_256(label).digest()
    hash_l1 = db[:hlen]

    # checagem para saber se for corretamente implementado
    if e_message[0] != 0: raise ValueError('Encripted message does not starts with 0x00')
    if not found: raise ValueError('Byte 0x01 not found between ps and message')
    if hash_l != hash_l1: raise ValueError('Hashes differ from each other')

    return message
