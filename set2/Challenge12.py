#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/2/challenges/12
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step anyways.

3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.

6. Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""

import sys

sys.path.insert(0, '../common/')

from common import generate_random_aes_key, encryption_oracle_ecb, oracle_detect_blockSize, detect_ecb_vs_cbc, oracle_matchByte
from Crypto.Random import random
import base64

def main():
	key = generate_random_aes_key()
	oracle = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

	## Detect blockSize
	blockSize, nIn = oracle_detect_blockSize(encryption_oracle_ecb, "", oracle, key)
	if blockSize == 0:
		print "! Failed to detect blockSize ..."
		exit(2)

	print "Detected blockSize: %d" % blockSize

	## Detect ECB
	input = 128 * '\x41'
	ct = encryption_oracle_ecb(input, oracle, key)
	ctDec = base64.b64decode(ct)
	ctLen = len(ctDec)

	if detect_ecb_vs_cbc(ct) == 0:
		print "! Failed to detect ECB ..."
		exit(2)

	print "Detected cipher mode ECB"

	## Detect Oracle len and decrypt it
	oracleLen = ctLen - len(input) - nIn

	plaintext = ''

	for y in range(oracleLen):
		n = (blockSize - len(plaintext) - 1) % blockSize
		input = n * '\x41'
		off = len(input) + len(plaintext) + 1
		ciphertext = encryption_oracle_ecb(input, oracle, key)
		ciphertext = base64.b64decode(ciphertext)
		ciphertextLen = len(ciphertext)
		ct1 = ciphertext[:off]

		curByte = oracle_matchByte(input, plaintext, oracle, key, off, ct1)
		if curByte == None:
			print "! Current byte not found ..."
			exit(2)

		plaintext += curByte


	if len(plaintext) > 0:
		print "\nPlaintext:\n\n%s" % plaintext
	else:
		print "Failed to decrypt oracle ..."
		exit(2)


if __name__ == '__main__':
	main()
