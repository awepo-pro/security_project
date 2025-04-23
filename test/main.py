import os
import time
import random 
import string
from test_rsa import rsa_encryption, rsa_decryption
from test_methods import *

# all key size are 24 
KEY_SIZE = 24
DATA_FILE = ['test_data.txt']

if not os.path.exists('dummy_test.txt'):
    with open('dummy_test.txt', 'w') as f:
        f.write('')

def gen_key(length, allowed_chars=string.ascii_letters + string.digits + ' ' + string.punctuation):
    return ''.join(random.choice(allowed_chars) for _ in range(length))

key = []

def test_rsa():
    for file in DATA_FILE:
        with open(file, 'r') as f:
            data = f.read()

        with open('dummy_test.txt', 'rb+') as target:
            target.write(rsa_encryption(file).encode('utf-8'))
            assert rsa_decryption('dummy_test.txt') == data, f"Decryption failed for {file}"

def test_rsa():
    for file in DATA_FILE:
        with open(file, 'r') as f:
            data = f.read()

        assert rsa_decryption(rsa_encryption(file)) == data, f"Decryption failed for {file}"

def test_triple_des():
    for file in DATA_FILE:
        with open(file, "rb") as f:
            data = f.read()

            for i in range(len(key)):
                cipher = TripleDES(str(key[i]).encode('utf-8'))
                result = cipher.encrypt(data)
            
                assert cipher.decrypt(result) == data, f"Decryption failed for {file}"
            
def test_aes():
    for file in DATA_FILE:
        with open(file, "rb") as f:
            data = f.read()

            for i in range(len(key)):
                cipher = AES(str(key[i]).encode('utf-8'))
                result = cipher.encrypt(data)
            
                assert cipher.decrypt(result) == data, f"Decryption failed for {file}"

def test_vigenere():
    key = [gen_key(KEY_SIZE, string.ascii_letters) for _ in range(int(1024 / KEY_SIZE))]

    for file in DATA_FILE:
    # Read/write text files
        with open(file, "r", encoding="utf-8") as f:
            data = f.read()

        for i in range(len(key)):
            cipher = Vigenere(key[i])
            
            result = cipher.encrypt(data)
            decrypted = cipher.decrypt(result)
            assert decrypted == data, f"Decryption failed for {file}"

def test(method, comment: str) -> None:
    print(comment)
    start = time.perf_counter()
    method()
    end = time.perf_counter()
    print(f'test finished in {end - start:.2f} seconds!')

def main():
    test(test_rsa, 'testing RSA')
    test(test_triple_des, 'testing 3 DES')
    test(test_aes, 'testing AES')
    test(test_vigenere, 'testing Vigenere')

    print('All tests passed!')

if __name__ == '__main__':
    key = [gen_key(KEY_SIZE) for _ in range(int(1024 / KEY_SIZE))]
    main()

    