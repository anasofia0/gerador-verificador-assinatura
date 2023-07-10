import sys
from AES import aes_encode, aes_decode, aes_ecb_cipher, aes_ecb_decipher
from key_gen import generate_keys, generate_pub_priv_keys
from RSA import OAEP_cipher, OAEP_decipher, RSA
import secrets
# implementando os casos de uso

def main(filename):

    with open(filename[0], 'r', encoding='utf-8') as f:
      message = f.read()

    print('Parte I: Cifração e decifração AES')

    key = int.to_bytes(generate_keys(1, 128)[0], 16, 'big')
    print(f'Chave gerada: {key}')
    e_message = aes_ecb_cipher(message, key)
    print(f'Mensagem cifrada: {e_message}')
    m = aes_ecb_decipher(e_message, key)
    print(f'Mensagem decifrada: {m}')

    print('Parte II: Geração de chaves e cifra RSA')
    
    p, q = generate_keys(2, 1024)
    private, public = generate_pub_priv_keys(p, q)
    print(f'Chave pública gerada: {public}')
    print(f'Chave privada gerada: {private}')

    e_message = OAEP_cipher(message, public, b'', generate_keys(1, 256)[0])
    print(f'Mensagem cifrada: {e_message}')
    m = OAEP_decipher(e_message, private, b'')
    print(f'Mensagem decifrada: {m}')
   

if __name__ == '__main__':
    main(sys.argv[1:])
