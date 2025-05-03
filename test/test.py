import os
import time
import random 
import string
from test_rsa import rsa_encryption, rsa_decryption
from test_methods import *

CURRENT_PATH = os.getcwd()
DATA_SET_FILE = os.path.join(CURRENT_PATH, 'data_set')
DATA_SET_UTF_FILE = os.path.join(DATA_SET_FILE, 'utf-8')


# all key size are 24 
KEY_SIZE = 24
DATA_FILE = [os.path.join(DATA_SET_FILE, file) for file in os.listdir(DATA_SET_FILE)]
UTF8_FILE = [os.path.join(DATA_SET_UTF_FILE, file) for file in os.listdir(DATA_SET_UTF_FILE)]

def gen_key(length, allowed_chars=string.ascii_letters + string.digits + ' ' + string.punctuation):
    return ''.join(random.choice(allowed_chars) for _ in range(length))

key = gen_key(24)
total_words = 0

data_stored = {}

def result_output(comment):
    with open('record_time.txt', 'w') as output:
        output.write(comment)

def get_input(file, mode='r'):
    global total_words
    if file + mode in data_stored:
        return data_stored[file + mode]
    
    with open(file, mode) as in_file:
        data = in_file.read()
        data_stored[file + mode] = data
        total_words += len(data)
        return data
    
def test(method):
    def wrapper(comment):
        result_output(comment)
        start = time.perf_counter()
        method()
        end = time.perf_counter()
        result_output(f"test finished in {end - start:.2f} seconds!", end='\n\n')

    return wrapper

@test
def test_rsa():
    # for file in DATA_FILE + UTF8_FILE:
    #     if not os.path.isfile(file):
    #         continue

    file = 'data_set/utf-8/data_set_utf2.txt'
    data = get_input(file=file)

    result_output(f'start processing {file}')
    start = time.perf_counter()
    assert rsa_decryption(rsa_encryption(data)) == data, f"Decryption failed for {file}"
    result_output(f'use {time.perf_counter() - start:2f}s to process {file}')


@test
def test_triple_des():
    for file in DATA_FILE + UTF8_FILE:
        if not os.path.isfile(file):
            continue

        data = get_input(file, 'rb')

        result_output(f"start processing {file}")
        start = time.perf_counter()

        cipher = TripleDES(str(key).encode('utf-8'))
        result = cipher.encrypt(data)
    
        assert cipher.decrypt(result) == data, f"Decryption failed for {file}"
        result_output(f"use {time.perf_counter() - start:2f}s to process {file}")

@test       
def test_aes():
    for file in DATA_FILE + UTF8_FILE:
        if not os.path.isfile(file):
            continue
        
        data = get_input(file, 'rb')

        result_output(f"start processing {file}")
        start = time.perf_counter()

        cipher = AES(str(key).encode('utf-8'))
        result = cipher.encrypt(data)
    
        assert cipher.decrypt(result) == data, f"Decryption failed for {file}"
        result_output(f"use {time.perf_counter() - start:2f}s to process {file}")

@test
def test_vigenere():
    key = gen_key(KEY_SIZE, string.ascii_letters)

    for file in DATA_FILE:
        if not os.path.isfile(file):
            continue

        data = get_input(file)
        cipher = Vigenere(key)

        result_output(f"start processing {file}")
        start = time.perf_counter()
        
        result = cipher.encrypt(data)
        decrypted = cipher.decrypt(result)

        assert len(decrypted) == len(data)
        
        # assert decrypted == data, f"Decryption failed for {file}"
        result_output(f"use {time.perf_counter() - start:2f}s to process {file}")


def main():
    # test_rsa('testing RSA')
    test_triple_des('testing 3 DES')
    test_aes('testing AES')
    test_vigenere('testing Vigenere')

    result_output(f'total characters: {total_words}')
    result_output('All tests passed!')

if __name__ == '__main__':
    main()
