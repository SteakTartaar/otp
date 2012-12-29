#!/usr/bin/python3

import sys

def err(msg):
	sys.stderr.write("Unrecoverable error: " + str(msg) + "\n")
	sys.exit()

class file:
	filename = ""
	handle = ""
	contents = ""
	mode = ""

	def __init__(self, filename, mode):
		self.filename = filename
		self.mode = mode
		self.handle = self.open()

	def open(self):
		try:
			return open(self.filename, self.mode)
		except Exception as ex:
			err("Unable to open file " + self.filename + " die to error: " + str(ex))

	def read(self):
		try:
			self.contents = self.handle.read()
		except Exception as ex:
			err("Unable to read file " + self.filename + " due to error: " + str(ex))

	def close(self):
		try:
			self.handle.close()
		except Exception as ex:
			err("Unable to close file " + self.filename + " due to error: " + str(ex))

