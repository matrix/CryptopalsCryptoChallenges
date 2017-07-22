#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/1/challenges/6 , https://cryptopals.com/static/challenge-data/6.txt
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test

and

wokka wokka!!!

is 37. Make sure your code agrees before you proceed.

3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.

5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.

7. Solve each block as if it was single-character XOR. You already have code to do this.

8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.


This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
"""

import sys
import base64
import string

from operator import itemgetter

sys.path.insert(0, '../common/')

from common import hamming, xor_with_key, character_frequency, xor_with_key_repeated

def main():
	filename = "challenge-data/6.txt"

	if hamming("this is a test", "wokka wokka!!!") != 37:
		print "Hamming distance is wrong!"
		exit(2)

	buffer = open(filename).read()
	ciphertext = base64.b64decode(buffer)
	ciphertext_len = len(ciphertext)

	KEYSIZE_values = []

	for KEYSIZE in range(2,40):
		first_KEYSIZE  = ciphertext[:KEYSIZE]
		second_KEYSIZE = ciphertext[KEYSIZE:KEYSIZE*2]
		edit_distance = hamming(first_KEYSIZE, second_KEYSIZE) / KEYSIZE
		KEYSIZE_values.append((edit_distance,KEYSIZE))

	sorted_KEYSIZE_values = sorted(KEYSIZE_values, key=itemgetter(0))

	for KEYSIZE_value in sorted_KEYSIZE_values:
		KEYSIZE = KEYSIZE_value[1]
		KEYSIZE_blockSize = KEYSIZE

		KEYSIZE_blocks = []
		tmp_block_len = 0

		for i in range(0, ciphertext_len, KEYSIZE_blockSize):
			KEYSIZE_block = ciphertext[i:i+KEYSIZE_blockSize]
			if tmp_block_len == 0:
				tmp_block_len = len(KEYSIZE_block)

			KEYSIZE_blocks.append(KEYSIZE_block)

		XOR_key = ""
		for i in range(0, tmp_block_len):
			KEYSIZE_block_transpose = ""
			for KEYSIZE_block in KEYSIZE_blocks:
				KEYSIZE_block_transpose += KEYSIZE_block[i:i+1]

			KEYSIZE_block_transpose = KEYSIZE_block_transpose.encode('hex')

			max_score = 0
			key = 0
			cur_ct = 0

			for cur_key in range(256):
				cur_ct = xor_with_key(KEYSIZE_block_transpose, cur_key)
				tmp = cur_ct.lower()

				if all(c in string.printable for c in tmp):
					score = character_frequency(tmp)

					if score > max_score:
						max_score = score
						key = cur_key
						ct = cur_ct

			if key != 0:
				pt = xor_with_key(ct, key)
				if all(c in string.printable for c in pt):
					XOR_key += chr(key)

		if len(XOR_key) > 0:
			plaintext = xor_with_key_repeated(ciphertext.encode('hex'), XOR_key)
			if all(c in string.printable for c in plaintext):
				if len(plaintext) == ciphertext_len:
					print "Key : %s" % XOR_key
					print plaintext
					exit(0)

if __name__ == '__main__':
	main()
