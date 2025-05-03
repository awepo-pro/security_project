import random
import os
import math

# def generate_prime(key_size):
# 	maximum = int(2 ** key_size)
# 	sieve = [True] * maximum

# 	for i in range(2, maximum):
# 		if sieve[i]:
# 			for j in range(i ** 2, maximum, i):
# 				sieve[j] = False

# 	return sieve

def x_gcd(a, b):
	if b == 0:
		return 1, 0, a

	ta, tb, gcd = x_gcd(b, a % b)
	return tb, ta - a // b * tb, gcd

def inv_mod(a, b):
	# x, y, gcd = x_gcd(a, b)
	# assert gcd == 1

	# return x if x >= 0 else x + b
 
	return pow(a, -1, b)

def gcd(a, b):
	if b == 0:
		return a

	return gcd(b, a % b)


# output true if num is prime, vice versa
def ranbin_miller(num):
	if num % 2 == 0 or num < 2:
		return False

	if num == 3:
		return True

	s = num - 1
	t = 0 

	while s % 2 == 0:
		s = s // 2
		t += 1

	for trials in range(5):
		a = random.randrange(2, num - 1)
		v = pow(a, s, num)

		if v != 1:
			i = 0

			while v != (num - 1):
				if i == t - 1:
					return False

				else:
					i = i + 1
					v = (v ** 2) % num

		return True

def generate_large_prime(bits_range):
	ret = 0
	while not ranbin_miller(ret):
		ret = random.randrange(bits_range[0], bits_range[1])

	return ret


# range within [2 ** keysize - 1, 2 ** keysize)
def generate_key(key_size):
	p, q = 0, 0

	# sieve = generate_prime(key_size)
	bits_range = (pow(2, key_size - 1), pow(2, key_size))

	while p == q:
		p = generate_large_prime(bits_range)
		q = generate_large_prime(bits_range)

	n = p * q
	e = 0
	A = (p - 1) * (q - 1)

	while e := random.randrange(bits_range[0], bits_range[1]):
		if e % 2 == 1 and math.gcd(e, A) == 1:
			break

	d = inv_mod(e, A)

	public_key = (n, e)
	private_key = (n, d)

	return public_key, private_key

def make_key_file(key_size, get_result=False):
	if get_result:
		return generate_key(key_size)

	else:
		file_name = input('file location: ')

		if os.path.exists(f'{file_name}2048_priv.txt') or os.path.exists(f'{file_name}2048_pub.txt'):
			exit('file exists! not wise to rewrite the file')

		public_key, private_key = generate_key(key_size)

		with open(f'{file_name}2048_priv.txt', 'w') as priv, open(f'{file_name}2048_pub.txt', 'w') as pub:
			print(f'{key_size}, {public_key[0]}, {public_key[1]}', file=priv, end='')
			print(f'{key_size}, {private_key[0]}, {private_key[1]}', file=pub, end='')

		print(f'exported to {file_name}2048_priv.txt and {file_name}2048_pub.txt!')

if __name__ == '__main__':
	make_key_file(2048)
