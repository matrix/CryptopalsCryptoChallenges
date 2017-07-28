#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/2/challenges/13
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
B. Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""

import sys

sys.path.insert(0, '../common/')

from common import generate_random_aes_key, k_v_parsing, profile_for, encrypt_userProfile, decrypt_userProfile, oracle_detect_blockSize_ch13, PKCS7_padding

import base64

def main():
	input = "foo=bar&baz=qux&zap=zazzle"
	print input

	print k_v_parsing(input)

	print profile_for("foo@bar.com")

	key = generate_random_aes_key()

	ct = encrypt_userProfile("foo@bar.com", key)

	print decrypt_userProfile(ct, key)

	# detect blockSize
	blockSize = oracle_detect_blockSize_ch13(encrypt_userProfile, key)
	if blockSize == 0:
		print "! Failed to detect blockSize ..."
		exit(2)

	print "Detected blockSize: %d" % blockSize

	# generate 'admin' profile
	ciphertext = ""

	ctLen = len(base64.b64decode(ct))

	# generate firsts valid ciphertext blocks
	n = 2
	input = (n * '\x41') + "foo@bar.com"
	curCT = encrypt_userProfile(input, key)
	curCTDec = base64.b64decode(curCT)
	curCTLen = len(curCTDec)

	# add blocks to ciphertext
	ciphertext += curCTDec[0:32]

	# generate 'admin' block
	input = "foo@bar.com" + (15 * '\x41') + PKCS7_padding("admin", 16);
	curCT = encrypt_userProfile(input, key)
	curCTDec = base64.b64decode(curCT)
	curCTLen = len(curCTDec)

	# add block to ciphertext
	ciphertext += curCTDec[32:32+16]

	# prepare ciphertext
	ciphertext = base64.b64encode(ciphertext)

	# decrypt modified ciphertext
	pt = decrypt_userProfile(ciphertext, key)
	print pt

if __name__ == '__main__':
	main()
