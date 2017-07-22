#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import string
import collections
import operator
import math
from itertools import izip, imap
from Crypto.Cipher import AES

## Common functions

def convert_hex_to_base64(input):
	x = input.decode('hex')
	return base64.b64encode(x)

def fixed_xor(buf1, buf2):
	if len(buf1) != len(buf2):
		return -1

	b1 = buf1.decode('hex')
	b2 = buf2.decode('hex')

	x = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))
	return x.encode('hex')

def english_word_frequency(buf):
	score = 0
	words = open('../common/english_top_3000_words.txt').read().splitlines()

	for word in words:
		w = word.lower()
		if w in buf:
			score += 30

	return score

def character_frequency(buf):
	score = 0
	b = buf.lower()
	letters = collections.Counter(b)

	for c in letters:
		if   c == 'e': score += 12.702
		elif c == 't': score += 9.056
		elif c == 'a': score += 8.167
		elif c == 'o': score += 7.507
		elif c == 'i': score += 6.966
		elif c == 'n': score += 6.749
		elif c == 's': score += 6.327
		elif c == 'h': score += 6.094
		elif c == 'r': score += 5.987
		elif c == 'd': score += 4.253
		elif c == 'l': score += 4.025
		elif c == 'c': score += 2.782
		elif c == 'u': score += 2.758
		elif c == 'm': score += 2.406
		elif c == 'w': score += 2.360
		elif c == 'f': score += 2.228
		elif c == 'g': score += 2.015
		elif c == 'y': score += 1.974
		elif c == 'p': score += 1.929
		elif c == 'b': score += 1.492
		elif c == 'v': score += 0.978
		elif c == 'k': score += 0.772
		elif c == 'j': score += 0.153
		elif c == 'x': score += 0.150
		elif c == 'q': score += 0.095
		elif c == 'z': score += 0.074

	return score

def xor_with_key(ciphertext, key):
	plaintext = ""

	if all(c in string.hexdigits for c in ciphertext):
		ct = ciphertext.decode('hex')

		for i in range(len(ct)):
			plaintext += chr(ord(ct[i]) ^ key)

	return plaintext

def single_byte_xor(ciphertext):
	max_score = 0
	key = 0
	plaintext = ""

	for cur_key in range(256):
		cur_pt = xor_with_key(ciphertext, cur_key)

		tmp = cur_pt.lower()
		if all(c in string.printable for c in tmp):
			c_score = character_frequency(tmp)
			w_score = english_word_frequency(tmp)
			score = c_score + w_score

			if score > max_score:
				max_score = score
				key = cur_key;

	return key, max_score

def xor_with_key_repeated(ciphertext, key):
	ct = ciphertext.decode('hex')
	plaintext = ""

	for i in range(len(ct)):
		keyIndex = i % len(key)
		plaintext += chr(ord(ct[i]) ^ ord(key[keyIndex]))

	return plaintext

def tobits(s):
	result = []
	for c in s:
		bits = bin(ord(c))[2:]
		bits = '00000000'[len(bits):] + bits
		result.extend([int(b) for b in bits])
	return result

def hamming(str1, str2):
	assert len(str1) == len(str2)
	ne = operator.ne
	s1 = tobits(str1)
	s2 = tobits(str2)

	return math.fsum(imap(ne, s1, s2))

def AES_ECB_decrypt(ciphertext, key):
	unpad = lambda s: s[:-ord(s[len(s) - 1:])]

	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = unpad(cipher.decrypt(ciphertext))

	return plaintext
