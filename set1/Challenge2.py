#!/usr/bin/python
# -*- coding: utf-8 -*-

""" URL: https://cryptopals.com/sets/1/challenges/2
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""

import sys
sys.path.insert(0, '../common/')

from common import fixed_xor

def main():
	input1 = str("1c0111001f010100061a024b53535009181c")
	input2 = str("686974207468652062756c6c277320657965")

	output = fixed_xor(input1, input2)
	print output

if __name__ == '__main__':
	main()
