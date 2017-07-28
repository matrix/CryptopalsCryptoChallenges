#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/2/challenges/14
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
"""

import sys

sys.path.insert(0, '../common/')

from common import generate_random_aes_key, oracle_detect_blockSize, encryption_oracle_ecb, detect_ecb_vs_cbc, oracle_matchByte, AES_ECB_encrypt
from Crypto import Random
from Crypto.Random import random

import base64
import string

def main():
	key = generate_random_aes_key()
	oracle = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

	## Random-Prefix
	cnt = random.randint(1, 1024);
	randomPrefix = Random.new().read(cnt)
	input = randomPrefix

	## Detect blockSize
	blockSize, nIn = oracle_detect_blockSize(encryption_oracle_ecb, str(randomPrefix), oracle, key)
	if blockSize == 0:
		print "! Failed to detect blockSize ..."
		exit(2)

	print "BlockSize: %d" % blockSize

	## Detect ECB
	input = randomPrefix + (nIn * '\x41') + (128 * '\x41')
	ct = encryption_oracle_ecb(input, oracle, key)
	ctDec = base64.b64decode(ct)
	ctLen = len(ctDec)

	if detect_ecb_vs_cbc(ct) == 0:
		print "! Failed to detect ECB ..."
		exit(2)

	## Detect Random-Prefix length
	rLenMax = 0
	for i in range(0, ctLen, blockSize):
		block = ctDec[i:i+blockSize]

		x = ctDec.count(block)
		if x > 2:
			rLenMax = i
			break

	if rLenMax == 0:
		print "Failed to find random-prefix length ..."
		exit(2)

	## Possible random-prefix length from rLenMax-16 to rLenMax
	## for each possible length, try decrypt oracle
	for i in range(rLenMax-16, rLenMax):

		randomPrefixLen = i
		oracleLen = ctLen - nIn - 128 - i

		iLen = randomPrefixLen
		while iLen % blockSize != 0:
			iLen += 1

		iLen = iLen - i;

		plaintext = ""
		failed = False

		for y in range(oracleLen):
			n = (blockSize - len(plaintext) - 1) % blockSize
			input = randomPrefix + (iLen * '\x48') + (n * '\x41')
			off = len(input) + len(plaintext) + 1
			ciphertext = encryption_oracle_ecb(input, oracle, key)
			ciphertext = base64.b64decode(ciphertext)
			ciphertextLen = len(ciphertext)
			ct1 = ciphertext[:off]

			curByte = oracle_matchByte(input, plaintext, oracle, key, off, ct1)
			if curByte == None:
				failed = True
				break

			plaintext += curByte

		if failed == False:
			break

	if len(plaintext) > 0:
		print "Detected 'Random-Prefix' length: %d\nDetected 'Oracle' length: %d\n" % (randomPrefixLen, oracleLen)
		print "Plaintext:\n\n%s" % plaintext


if __name__ == '__main__':
	main()
