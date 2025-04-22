import os 
import math
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.,<>()*\n\t\''
PUBLIC_KEY_FILE = f'{BASE_DIR}/hello_pub.txt'
PRIVATE_KEY_FILE = f'{BASE_DIR}/hello_priv.txt'

sys.path.append(BASE_DIR)
from make_key import make_key_file

def get_public_key():
	key_size, n, e = 0, 0, 0
	with open(PUBLIC_KEY_FILE, 'r') as target:
		key_size, n, e = target.readline().split(', ')

	return int(key_size), int(n), int(e)

def public_key_encryption(msg, key, block_size):
	ret = []
	n, e = key

	for start_idx in range(0, len(msg), block_size):
		value = 0

		# ch * (66 ^ i)
		for i in range(start_idx, min(start_idx + block_size, len(msg))):
			value += SYMBOLS.find(msg[i]) * pow(len(SYMBOLS), i % block_size)

		# C = M^e (mod n)
		ret.append(str(pow(value, e, n)))

	# separate blocks by ', ''
	return ', '.join(ret)

def rsa_encryption(msg_file, block_size=None):
	global SYMBOLS
	with open(msg_file, 'r') as target:
		msg = target.read()
  
		for x in msg:
			if x not in SYMBOLS:
				SYMBOLS += x

	if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
		key_size = 1024
		pub_key, pri_key = make_key_file(key_size, True)
		with open(PUBLIC_KEY_FILE, 'w') as pub, open(PRIVATE_KEY_FILE, 'w') as pri:
			print(f'{key_size}, {pub_key[0]}, {pub_key[1]}', file=pri, end='')
			print(f'{key_size}, {pri_key[0]}, {pri_key[1]}', file=pub, end='')
			print('[DEBUG]: keys generated!')
        
	key_size, n, e = get_public_key()

	# 2 ** key_size > len(SYMBOLS) ** block_size => lg(2 ** key_size) / lg(SYMBOLS) > block_size
	if block_size is None:
		block_size = int(math.log(2 ** key_size) // len(SYMBOLS))
	elif not math.log(2 ** key_size, len(SYMBOLS)) >= block_size:
		exit('block_size is too large')

	encrypted_msg = public_key_encryption(msg, (n, e), block_size)

	# with open(f'{BASE_DIR}/magic_encryption.txt', 'w') as target:
	# 	print(f'{len(msg)}_{block_size}_{encrypted_msg}', file=target, end='')
  
	return f'{len(msg)}_{block_size}_{encrypted_msg}'

def dencryption(encrypted_msg, msg_len, key, block_size):
	n, d = key
	encrypted_msg = [pow(int(x), d, n) for x in encrypted_msg]
	ret = []

	for msg_value in encrypted_msg:
		msg = []

		for i in range(block_size - 1, -1, -1):
			# last-block's size might <= block_size
			if len(ret) + i < msg_len:
				char_idx = msg_value // (len(SYMBOLS) ** i)
				msg_value = msg_value % (len(SYMBOLS) ** i)
    
				if char_idx >= len(SYMBOLS):
					msg.insert(0, '<UNK>')
				else:
					msg.insert(0, SYMBOLS[char_idx])

		ret.extend(msg)

	return ''.join(ret)

def get_private_key(key):
	key_size, n, d = 0, 0, 0

	if key == '' or key is None:
		if not os.path.exists(PRIVATE_KEY_FILE):
			print('[DEBUG]: private key not found!')
			exit(1)
			
		with open(f'{BASE_DIR}/hello_priv.txt') as target:
			key_size, n, d = target.read().split(', ')
	else:
		key_size, n, d = key.split(', ')

	return int(key_size), int(n), int(d)

def read_file(msg_file):
	msg_len, block_size, encrypted_msg = 0, 0, 0

	with open(msg_file) as target:
		msg_len, block_size, encrypted_msg = target.read().split('_')

	return int(msg_len), int(block_size), encrypted_msg

def rsa_decryption(msg_file, key=None):
	key_size, n, d = get_private_key(key)
	msg_len, block_size, encrypted_msg = read_file(msg_file)

	encrypted_msg = [x for x in encrypted_msg.split(', ')]
	return dencryption(encrypted_msg, msg_len, (n, d), block_size)


if __name__ == '__main__':
	msg_file = '123.txt'
	rsa_encryption(msg_file, 10)
	print(rsa_decryption('magic_encryption.txt'))
