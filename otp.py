#!/usr/bin/env python

import sys
import argparse
import os
import string
import random

open_files = []

def close_all():
	for open_file in open_files:
		open_file.close()
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

	def write(self, data):
		try:
			self.handle.write(data)
			alert("Written to '" + self.fn + "'")
		except Exception as ex:
			err("Unable to write to file '" + self.fn + "' due to error: " + str(ex))

	def close(self):
		try:
			self.handle.close()
			open_files.remove(self)
			alert("Closed '" + self.fn + "'")
		except Exception as ex:
			alert("Unable to close file '" + self.fn + "' due to error: " + str(ex))

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
	key = None
	src = None

	def __init__(self, _in, _out, key):
		self._in = _in
		self._out = _out
		self.key = key

	def encrypt(self):
		pass

	def decrypt(self):
		pass

	def gen_key(self):
		pass

def test():
	random = rand()
	outfile = _file("out", "w")
	bits = rand().get_rand(5)
	outfile.write(bits)
	close_all()


test()



