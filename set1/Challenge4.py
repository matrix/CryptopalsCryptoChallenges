#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/1/challenges/4 , https://cryptopals.com/static/challenge-data/4.txt
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""

import sys
sys.path.insert(0, '../common/')

from common import single_byte_xor, xor_with_key

def main():
	filename = "challenge-data/4.txt";
	max_score = 0
	key = 0
	ciphertext = 0

	lines = open(filename).read().splitlines()
	for cur_ct in lines:
		tmp = single_byte_xor(cur_ct)
		cur_key = tmp[0]
		score = tmp[1]

		if score > max_score:
			max_score = score
			key = cur_key
			ciphertext = cur_ct

	if key != 0:
		print "Ciphertext: %s" % ciphertext
		print "Key : %c" % chr(key)
		plaintext = xor_with_key(ciphertext,key)
		print "Plaintext: %s" % plaintext

if __name__ == '__main__':
	main()
