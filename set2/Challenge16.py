#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/2/challenges/16
CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

- Completely scrambles the block the error occurs in
- Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?
"""

import sys

sys.path.insert(0, '../common/')

from common import AES_CBC_encrypt, AES_CBC_decrypt, PKCS7_unpadding

import base64
import binascii

def encrypt_cbc_ch16(input, key):
	input = input.replace(";","%3b").replace("=","%3d")
	input = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon"

	return AES_CBC_encrypt(input, key, False)

def decrypt_cbc_ch16(input, key):
	plaintext = AES_CBC_decrypt(input, key)

	if ";" in plaintext:
		pt = plaintext.split(';')
		for p in pt:
			if p == "admin=true":
				print "Plaintext: %s" % plaintext
				return True

	return False

def main():
	key = "0123456789abcdef"

	input = "QWERTYXadminYtrue"
	ct = encrypt_cbc_ch16(input, key)

	ct = base64.b64decode(ct)
	ctLen = len(ct)

	check = False
	for i in range(0, ctLen):
		ct2 = ct

		# flipping 'Y' to '='
		x = chr(ord('Y') ^ ord('=') ^ ord(ct2[i]))
		ct2 = ct2[0:i] + x + ct2[i+1:]

		# offset of 'X'
		n = i - 6

		# flipping 'X' to ';'
		x = chr(ord('X') ^ ord(';') ^ ord(ct2[n]))
		ct2 = ct2[0:n] + x + ct2[n+1:]

		ct2 = base64.b64encode(ct2)

		try:
			check = decrypt_cbc_ch16(ct2, key)
			if check == True:
				print "Attack done"
				break
		except:
			continue

	if check == False:
		print "Attack failed ..."
		exit(2)

if __name__ == '__main__':
	main()
