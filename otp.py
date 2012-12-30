#!/usr/bin/env python

import sys
import argparse
import os
import string
import random

open_files = []
block_size = 65536

def close_all():
	for _file in open_files:
		_file.close()
	alert("Closed all open files")

def err(msg):
	sys.stderr.write("[X] Unrecoverable error: " + str(msg) + "\n")
	sys.exit()

def alert(msg):
	print("[!] " + str(msg))

def get_args():
	pass

class _file:
	fn = None
	handle = None
	cont = None
	mode = None

	def __init__(self, fn, mode):
		self.fn = fn
		self.mode = mode
		self.handle = self.open()
		open_files.append(self)

	def open(self):
		try:
			handle = open(self.fn, self.mode)
			alert("Opened '" + self.fn + "'")
			return handle
		except Exception as ex:
			err("Unable to open file '" + self.fn + "' due to error: " + str(ex))

	def read(self):
		try:
			cont = self.handle.read()
			alert("Read '" + self.fn + "'")
			return cont
		except Exception as ex:
			err("Unable to read file '" + self.fn + "' due to error: " + str(ex))

	def read(self, size):
		try:
			cont = self.handle.read(size)
			alert("Read " + str(size) + " of '" + self.fn + "'")
			return cont
		except Exception as ex:
			err("Unable to read file '" + self.fn + "' due to error: " + str(ex))

	def write(self, data):
		try:
			self.handle.write(data)
			alert("Data written to '" + self.fn + "'")
		except Exception as ex:
			err("Unable to write to file '" + self.fn + "' due to error: " + str(ex))

	def close(self):
		try:
			open_files.remove(self)
			self.handle.close()
			alert("Closed '" + self.fn + "'")
		except Exception as ex:
			alert("Unable to close file '" + self.fn + "' due to error: " + str(ex))

	def get_size(self):
		self.handle.seek(0,2)
		size = self.handle.tell()
		self.handle.seek(0,0)
		alert("The size of the input file is " + str(size))
		return size

class rand:
	src = None
	def __init__(self):
		if os.path.exists('/dev/urandom'):
			self.src = open('/dev/urandom', 'r')
		elif os.path.exists('/dev/random'):
			self.src = open('/dev/random', 'r')

	def get_rand(self, size):
		if self.src == None:
			return self.get_py_rand(size)
		else:
			return self.get_sys_rand(size)

	def get_py_rand(self, size): 
		return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(size))

	def get_sys_rand(self, size):
		return self.src.read(size)

class crypt:
	_in = None
	_out = None
	_key = None
	src = None

	def __init__(self,infile, outfile, keyfile):
		self._in = _file(infile, "r")
		self._out = _file(outfile, "w")
		if (os.path.exists(keyfile)):
			self._key = _file(keyfile, "r")
		else:
			self.key = _file(keyfile, "w+")
		self.src = rand()
		self.process()

	def encrypt(self):
		alert("Encrypting '" + self._in.fn + "'")
		self.gen_key()
		self.process()

	def decrypt(self):
		alert("Decrypting " + self._in.fn + "'")
		self.process()

	def process(self):
		self._key.handle.seek(0)
		while 1:
			data = self._in.read(block_size)
			if not data:
				break
			key = self._key.read(len(data))
			encrypted = ''.join([chr(ord(data_in) ^ ord(data_out)) for data_in, data_out in zip(data, key)])
			self._out.write(encrypted)

	def gen_key(self):
		alert("Generating key for '" + self._in.fn + "'")
		key = ""
		total = self._in.get_size()
		while total > 0:
			block = self.src.get_rand(min(block_size, total))
			key += block
			total = total - len(block)
		self._key.write(key)
		return key

class cloaker:
	png = None
	png_out = None

	def __init__(self, fn):
		png = _file(png, "r")
		png_out = _file(png + "_out", "w")

def test():
	crypto = crypt("infile.txt", "outfile.txt", "key.txt")
	crypto.decrypt()
	close_all()


test()



