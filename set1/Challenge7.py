#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/1/challenges/7 , https://cryptopals.com/static/challenge-data/7.txt
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
"""

import sys
import base64

sys.path.insert(0, '../common/')

from common import AES_ECB_decrypt

def main():
	filename = "challenge-data/7.txt"
	key = "YELLOW SUBMARINE"

	buffer = open(filename).read()
        ciphertext = base64.b64decode(buffer)
	plaintext = AES_ECB_decrypt(ciphertext, key)

	print plaintext

if __name__ == '__main__':
	main()
