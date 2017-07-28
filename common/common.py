#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import string
import collections
import operator
import math
import struct

from itertools import izip, imap
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

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

def AES_ECB_encrypt(plaintext, key):
	plaintext = PKCS7_padding(plaintext, AES.block_size)

	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(plaintext)

	return base64.b64encode(ciphertext)

def AES_ECB_decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)

	ciphertext = base64.b64decode(ciphertext)
	plaintext = cipher.decrypt(ciphertext)

	return PKCS7_unpadding(plaintext, AES.block_size)

def PKCS7_padding(input, blockSize):
	n = len(input) % blockSize
	if n != 0:
		n = blockSize - n

	v = struct.pack('>b', n)

	while len(input) % blockSize != 0:
		input += v

	return input

def PKCS7_unpadding(input, blockSize):
	x = ord(input[-1])

	if x > blockSize:
		return input

	y = len(input) - x
	pad = input[y:]

	if pad.count(input[-1]) != x:
		raise ValueError("Invalid padding (bytes)")

	return input[:y]

def AES_CBC_encrypt_iv(plaintext, key, iv):
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = PKCS7_padding(plaintext, AES.block_size)

	plaintext_len = len(plaintext)

	ciphertext = iv
	for i in range(0, plaintext_len, AES.block_size):
		block = plaintext[i:i+AES.block_size]

		ct = xor_with_key_repeated(block.encode('hex'), iv)
		ct = cipher.encrypt(ct)

		iv = ct
		ciphertext += ct

	return base64.b64encode(ciphertext)

def AES_CBC_encrypt(plaintext, key, zeroIV):
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = PKCS7_padding(plaintext, AES.block_size)

	if zeroIV == True:
		iv = AES.block_size * '\x00'
	else:
		iv = Random.new().read(AES.block_size)

	plaintext_len = len(plaintext)

	ciphertext = iv
	for i in range(0, plaintext_len, AES.block_size):
		block = plaintext[i:i+AES.block_size]

		ct = xor_with_key_repeated(block.encode('hex'), iv)
		ct = cipher.encrypt(ct)

		iv = ct
		ciphertext += ct

	return base64.b64encode(ciphertext)

def AES_CBC_decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = base64.b64decode(ciphertext)

	iv = ciphertext[:AES.block_size]
	ciphertext = ciphertext[AES.block_size:]
	ciphertext_len = len(ciphertext)

	plaintext = ""
	for i in range(0, ciphertext_len, AES.block_size):
		block = ciphertext[i:i+AES.block_size]
		tmp = block

		pt = cipher.decrypt(block)
		pt = xor_with_key_repeated(pt.encode('hex'), iv)

		iv = tmp
		plaintext += pt

	return PKCS7_unpadding(plaintext, AES.block_size)

def generate_random_aes_key():
	return Random.new().read(AES.block_size)

def encryption_oracle(input):
	key = generate_random_aes_key()
	cntIN = random.randint(5, 10);
	cntOUT = random.randint(5, 10);

	newInput = ''.join(random.choice(string.ascii_uppercase) for x in range(cntIN)) + input + ''.join(random.choice(string.ascii_uppercase) for x in range(cntOUT))

	choose = random.randint(0, 1)

	if choose == 0:
		print "Encrypt '%s' using AES ECB ..." % newInput
		return AES_ECB_encrypt(newInput, key)
	else:
		print "Encrypt '%s' Using AES CBC ..." % newInput
		return AES_CBC_encrypt(newInput, key, False)

def detect_ecb_vs_cbc(ciphertext):
	buffer = base64.b64decode(ciphertext)
	bufferLen = len(buffer)

	n = 0
	for i in range(0, bufferLen, 16):
		curBlock = buffer[i:i+16]
		other = buffer[i+16:]

		n += other.count(curBlock)

	if n > 0:
		print "ECB detected : some ciphertext blocks are repeated %d time(s)" % n
	else:
		print "CBC detected : ciphertext without repetitions"

	return n

def encryption_oracle_ecb(input, oracle, key):
	newInput = input + base64.b64decode(oracle)
	return AES_ECB_encrypt(newInput, key)

def oracle_detect_blockSize(func, prefix, oracle, key):
	blockSize = 0

	ct = func(prefix, oracle, key)
	ctDec = base64.b64decode(ct)
	ctLen = len(ctDec)

	for i in range(0, 64):
		input = prefix + (i * '\x41')

		curCT = func(input, oracle, key)
		curCTDec = base64.b64decode(curCT)
		curCTLen = len(curCTDec)

		if curCTLen != ctLen:
			blockSize = curCTLen - ctLen
			break

	return blockSize, (i-1)

def oracle_detect_blockSize_ch13(func, key):
	blockSize = 0

	ct = func("", key)
	ctDec = base64.b64decode(ct)
	ctLen = len(ctDec)

	for i in range(0, 64):
		input = i * '\x41'

		curCT = func(input, key)
		curCTDec = base64.b64decode(curCT)
		curCTLen = len(curCTDec)

		if curCTLen != ctLen:
			blockSize = curCTLen - ctLen
			break

	return blockSize

def oracle_matchByte(input, plaintext, oracle, key, offset, matchBytes):
	for i in range(0, 256):
		input2 = input + plaintext + chr(i)

		ct = encryption_oracle_ecb(input2, oracle, key)
		ct = base64.b64decode(ct)
		ctLen = len(ct)
		ct2 = ct[:offset]

		if matchBytes == ct2:
			return chr(i)

	return None

def k_v_parsing(input):
	json = "{\n"

	buffer = input.split('&')
	bufferSize = len(buffer)

	i = 1
	for buf in buffer:
		data = buf.split('=')
		json += "  %s: '%s'" % (data[0], data[1])

		if i != bufferSize:
			json += ","

		json += "\n"
		i += 1

	json += "}"

	return json

def profile_for(email):
	return "email=" + email.replace("&", "%26").replace("=", "%3d") + "&uid=10&role=user"

def encrypt_userProfile(input, key):
	plaintext = profile_for(input)
	return AES_ECB_encrypt(plaintext, key)

def decrypt_userProfile(ciphertext, key):
	plaintext = AES_ECB_decrypt(ciphertext, key)
	return k_v_parsing(plaintext)

