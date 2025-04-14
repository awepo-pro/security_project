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
