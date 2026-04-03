#!/usr/bin/env python3
"""
Shamir's Secret Sharing Implementation
"""

import os


def gf256_mul(a, b):
	result = 0
	while b:
		if b & 1:
			result ^= a
		a = (a << 1) ^ (0x11B if a & 0x80 else 0)
		b >>= 1
	return result & 0xFF


def gf256_exp(base, exp):
	result = 1
	for _ in range(exp):
		result = gf256_mul(result, base)
	return result


def gf256_inv(a):
	if a == 0:
		return 0
	return gf256_exp(a, 254)


def gf256_div(a, b):
	if b == 0:
		raise ValueError('Division by zero')
	return gf256_mul(a, gf256_inv(b))


class ShamirSecretSharing:
	@classmethod
	def generate_shares(cls, secret, num_shares, threshold):
		if threshold > num_shares:
			raise ValueError('Threshold cannot exceed number of shares')
		if threshold < 2:
			raise ValueError('Threshold must be at least 2')
		if len(secret) == 0:
			raise ValueError('Secret cannot be empty')

		# Generate random coefficients ONCE for the polynomial (same for all shares!)
		coeffs = [os.urandom(1)[0] for _ in range(threshold - 1)]

		shares = []
		for i in range(num_shares):
			share = bytearray(len(secret) + 1)
			share[0] = i + 1
			x = i + 1

			# Evaluate the SAME polynomial at different x values
			for j in range(len(secret)):
				y = secret[j]
				for deg in range(1, threshold):
					y ^= gf256_mul(coeffs[deg - 1], gf256_exp(x, deg))
				share[j + 1] = y

			shares.append(bytes(share))

		return shares

	@classmethod
	def recover_secret(cls, shares):
		if len(shares) < 2:
			raise ValueError('At least 2 shares required for recovery')
		if len({share[0] for share in shares}) != len(shares):
			raise ValueError('Duplicate shares are not allowed for recovery')

		secret_length = len(shares[0]) - 1
		secret = bytearray(secret_length)

		for j in range(secret_length):
			x_vals = [s[0] for s in shares]
			y_vals = [s[j + 1] for s in shares]

			result = 0
			for i in range(len(shares)):
				num = 1
				den = 1
				for m in range(len(shares)):
					if m != i:
						num = gf256_mul(num, x_vals[m])
						den = gf256_mul(den, x_vals[m] ^ x_vals[i])
				li = gf256_div(num, den)
				result ^= gf256_mul(y_vals[i], li)

			secret[j] = result

		return bytes(secret)


if __name__ == '__main__':
	secret = b'my-secret-key-12345678901234'
	print('Original secret:', secret.hex())

	shares = ShamirSecretSharing.generate_shares(secret, 3, 2)
	print('\nGenerated 3 shares (threshold 2):')
	for i, share in enumerate(shares):
		print(f'Share {i + 1}:', share.hex())

	recovered = ShamirSecretSharing.recover_secret([shares[0], shares[1]])
	print('\nRecovered with shares 1 & 2:', recovered.hex())

	recovered2 = ShamirSecretSharing.recover_secret([shares[0], shares[2]])
	print('Recovered with shares 1 & 3:', recovered2.hex())

	print('\nTest passed:', secret == recovered and secret == recovered2)
