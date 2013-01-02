#!/usr/bin/env python

# required for file existence checking and clean exits
import sys
import os

# parse command line arguments in a clean way
import argparse

# used for generating random keys; string required if /dev/(u)random
# isunavailable
import string
import random

# keeps track of opened files for the clean close function
open_files = []


def alert(msg):
    # simple command line messaging system
    print("[!] " + str(msg))


def err(msg):
    # gracefully exit after unrecoverable error
    sys.stderr.write("[X] Unrecoverable error: " + str(msg) + "\n")
    try:
        close_all()
    except Exception as ex:
        alert("Error closing files: " + str(ex))
    sys.exit(1)


def decode(msg):
    # function to decode bytes with UTF-8 encoding
    return msg.decode("utf-8")


def close_all():
        # In case of trapped fatal exception: close all open files
    num = 0
    for item in open_files:
        item.close()
        num += 1
    alert("Closed " + str(num) + " open files")


class rand:
    # create a source of random data and read arbitrary chunks
    src = None

    def __init__(self):
        # check for POSIX standard sources
        if os.path.exists('/dev/urandom'):
            self.src = _file('/dev/urandom', 'r')
        elif os.path.exists('/dev/random'):
            self.src = _file('/dev/random', 'r')

    def get_rand(self, size):
        # wrapper that delegates to current source of random data
        if self.src == None:
            return self.get_py_rand(size)
        else:
            return self.get_sys_rand(size)

    def get_py_rand(self, size):
        # 'cheap' randomizer that gets input from Python's random function
        return ''.join(random.choice(string.ascii_letters + string.digits)
                       for i in range(size))

    def get_sys_rand(self, size):
        # get random data by reading /dev/(u)random
        return self.src.read(size)


class _file:
    # ugly, ugly wrapper around the built-in file()
    # catches IO exceptions and allows me to alias some file operand commands
    # file() itself seems to be an interface to stdio...

    fn = None
    fd = None
    mode = None

    def __init__(self, fn, mode):
        self.fn = fn
        self.mode = mode
        self.fd = self.open()

    def open(self):
        try:
            fd = open(self.fn, self.mode)
            open_files.append(fd)
            alert("Opened '" + self.fn + "'")
            return fd
        except Exception as ex:
            err("Unable to open file '" + self.fn + "'' due to error: "
                + str(ex))

    def read(self, size):
        try:
            data = self.fd.read(size)
            alert("Read " + str(size) + " from file '" + self.fn + "'")
            return data
        except Exception as ex:
            err("Unable to read from file '" + self.fn + "' due to error: "
                + str(ex))

    def write(self, data):
        try:
            self.fd.write(data)
            alert("Data written to '" + self.fn + "'")
        except Exception as ex:
            err("Unable to write data to '" + self.fn +
                "'due to error: " + str(ex))

    def close(self):
        try:
            self.fd.close()
            open_files.remove(self)
            alert("Closed '" + self.fn + "'")
        except Exception as ex:
            err("Unable to close file '" + self.fn + "' due to error: " +
                str(ex))

    def reset_ptr(self):
        # return pointer to start of file
        self.fd.seek(0, 0)

    def move_ptr(self, a, b):
        # move pointer to position
        self.fd.seek(a, b)

    def move_ptr(self, pos):
        # move pointer to position
        self.fd.seek(pos)

    def get_size(self):
        # return size of opened file
        try:
            self.move_ptr(0, 2)
            size = self.fd.tell()
            self.reset_ptr()
            return size
        except Exception as ex:
            alert("Unable to move pointer due to: " + str(ex))


class crypt:
        # encryption and decryption class
        # constructor takes three arguments:
        # an input file (exists), an output file (new)
        # and a keyfile
        # if the keyfile doesn't exist, a new one is generated

    _in = None
    _out = None
    _key = None
    rand = None
    block_size = 65536

    def __init__(self, infile, outfile, _keyfile):
        self._in = _file(infile, "r")
        self._out = _file(outfile, "w")
        if keyfile != None:
            self._key = _keyfile
        else:
            self._key = _file("keyfile", "w+")
            self.src = rand()
            self.gen_key()

    def gen_key(self):
        # generate key of the same size as the input file
        alert("No key found, generating...")
        key = ""
        size = self._in.get_size()
        while size > 0:
            block = self.src.get_rand(min(self.block_size, size))
            key += block
            size = size - (len(block))
            self._key.write(key)

    def process(self):
        # OTP algorithm used here goes two ways, so the same code
        # handles encryption and decryption
        # originally this printed chunks of the key to console for debugging
        # but that stopped once it accidentally generated 'bell'
        self._key.reset_ptr()
        while 1:
            data = self._in.read(self.block_size)
            if not data:
                break
            key = self._key.read(len(data))
            # the heart of the algorithm: the magic of binary XOR
            encrypted = ''.join([chr(ord(data_in) ^ ord(data_out))
                                 for data_in, data_out in zip(data, key)])
            # writing in small chunks - bad for IO, but good for debugging
            self._out.write(encrypted)


class _png(_file):
    # specialized class with additional means of accessing png files
    # extends _file

    mode = "rb+"
    headers = []

    def __init__(self, fn):
        self.fn = fn
        self.fd = self.open()
        if !self.is_png:
            err("This is not a PNG file")

    def is_png(self):
        # compares first eight bytes of file with the PNG standard
        self.reset_ptr()
        data = self.read(8)
        self.reset_ptr()
        dec = []
        # the magic numbers - see
        # http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
        std = [137, 80, 78, 71, 13, 10, 26, 10]
        for element in data:
            dec.append(ord(element))
        return dec == std

def test():

    png = _png("red.png")
    png.reset_ptr()
    png.move_ptr(9)
    print(png.read(16))
    close_all()

test()
