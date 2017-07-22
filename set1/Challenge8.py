#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/1/challenges/8 , https://cryptopals.com/static/challenge-data/8.txt
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

import sys

sys.path.insert(0, '../common/')

def main():
	filename = "challenge-data/8.txt"

	lines = open(filename).read().splitlines()

	for ct in lines:
		ct_len = len(ct)
		blockSize = 16

		for i in range(0, ct_len, blockSize):
			block = ct[i:i+blockSize];
			tmp = ct[i+blockSize:]

			if block in tmp:
				print "Found same ciphertext block '%s' in line %s" % (block, ct)

if __name__ == '__main__':
	main()
