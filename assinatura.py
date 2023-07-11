import sys
from AES import aes_ecb_cipher, aes_ecb_decipher
from key_gen import generate_keys, generate_pub_priv_keys
from RSA import OAEP_cipher, OAEP_decipher, RSA
from hashlib import sha3_256
import base64

def main(filename):

    with open(filename[0], 'r', encoding='utf-8') as f:
      message = f.read()

    print('Parte I: Cifração e decifração AES\n')

    # gerando um primo de 128 bits
    key = int.to_bytes(generate_keys(1, 128)[0], 16, 'big')
    print(f'Chave gerada: {key}\n')
    # cifrando mensagem com aes
    e_message = aes_ecb_cipher(message, key)
    print(f'Mensagem cifrada: {e_message}\n')
    # decifrando mensagem com aes
    m = aes_ecb_decipher(e_message, key)
    print(f'Mensagem decifrada: {m}\n')

    print('Parte II: Geração de chaves e cifra RSA\n')
    
    # gerando p e q
    p, q = generate_keys(2, 1024)
    
    # gerando chaves pública e privada
    private, public = generate_pub_priv_keys(p, q)
    print(f'Chave pública gerada:\n\tn: {public[0]}\n\te: {public[1]}\n')
    print(f'Chave privada gerada:\n\tn: {private[0]}\n\td: {private[1]}\n')

    message = bytes(message, 'utf-8')

    # cifrando com OAEP e RSA
    e_message = OAEP_cipher(message, public, b'', generate_keys(1, 256)[0])
    print(f'Mensagem cifrada: {e_message}\n')
    # decifrando com OAEP e RSA
    m = OAEP_decipher(e_message, private, b'')
    print(f'Mensagem decifrada: {m}\n')

    print('Parte III: Assinatura RSA\n')

    p, q = generate_keys(2, 1024)
    private, public = generate_pub_priv_keys(p, q)

    # gerando hash da mensagem
    hash_m = sha3_256(message).digest()
    # assinando mensagem
    e_hash = RSA(int.from_bytes(hash_m, 'big'), private[1], private[0])
    e_hash = e_hash.to_bytes((e_hash.bit_length()+7)//8, 'big')
    # codificando para base 64
    sign = base64.b64encode(e_hash)

    print(f'Mensangem assinada: {sign}\n')

    print('Parte IV: Verificação\n')

    # decodificando de base 64
    dec_sign = base64.b64decode(sign)
    dec_sign = int.from_bytes(dec_sign, 'big')
    # obtendo hash da mensagem
    dec_sign = RSA(dec_sign, public[1], public[0])

    # verificando se hashes batem
    if dec_sign == int.from_bytes(hash_m, 'big'):
      print('Sucesso')
    else:
      print('Falhamo')

if __name__ == '__main__':
    main(sys.argv[1:])
