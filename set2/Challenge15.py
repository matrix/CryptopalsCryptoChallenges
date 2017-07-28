#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/2/challenges/15
PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""

import sys

sys.path.insert(0, '../common/')

from common import PKCS7_unpadding

def main():
	input = "ICE ICE BABY\x04\x04\x04\x04"
	output = "ICE ICE BABY"

	if PKCS7_unpadding(input, 16) != output:
		print "Test1: failed"
		exit(2)

	print "Test1: done"

	try:
		input = "ICE ICE BABY\x05\x05\x05\x05"
		PKCS7_unpadding(input, 16)
		print "Test2: failed"
		exit(2)
	except ValueError:
		print "Test2: done, got ValueError exception"

	try:
		input = "ICE ICE BABY\x01\x02\x03\x04"
		PKCS7_unpadding(input, 16)
		print "Test3: failed"
		exit(2)
	except ValueError:
		print "Test3: done, got ValueError exception"

	print "All tests are done"


if __name__ == '__main__':
	main()
