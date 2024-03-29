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

# create bigendian ints for the PNG chunks
import struct

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


def get_args():
    # create, populate and return an argument parser
    parser = argparse.ArgumentParser(description="One Time Pad encryption")
    parser.add_argument('infile')
    parser.add_argument('outfile')
    #parser.add_argument('image')
    return parser.parse_args()


class rand:
    # create a source of random data and read arbitrary chunks
    src = None

    def __init__(self):
        # check for POSIX standard sources
        if os.path.exists('/dev/random'):
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
            err("Unable to open file '" + self.fn + "' due to error: "
                + str(ex))

    def read(self, size):
        try:
            data = self.fd.read(size)
            alert("Read " + str(size) + " from file '" + self.fn + "'")
            if data:
                return data
            else:
                alert("Tried reading data but none found, assuming EOF")
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
            alert("Closed '" + self.fn + "'")
        except Exception as ex:
            err("Unable to close file '" + self.fn + "' due to error: " +
                str(ex))
        try:
            open_files.remove(self)
        except Exception as ex:
            pass

    def reset_ptr(self):
        # return pointer to start of file
        self.move_ptr(0, 0)

    def move_ptr(self, *args):
        # overloaded method to move the pointer within a file
        if len(args) == 1:
            try:
                alert("Moving pointer to " + str(args[0]))
                self.fd.seek(args[0])
            except Exception as ex:
                err("Unable to move pointer due to " + str(ex))
        elif len(args) == 2:
            try:
                alert("Moving pointer to " + str(args[0]) + ", " + str(args[1]))
                self.fd.seek(args[0], args[1])
            except Exception as ex:
                alert(str(args[0]) + " " + str(args[1]))
                err("Unable to move pointer due to " + str(ex))
        else:
            err("Only two arguments allowed")

    def get_size(self):
        # return size of opened file
        self.move_ptr(0, 2)
        size = self.fd.tell()
        self.reset_ptr()
        return size


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

    def __init__(self, infile, outfile):
        # open the source file, output file, and the temporary keyfile
        self._in = _file(infile, "rb")
        self._out = _file(outfile, "wb")
        if os.path.exists("key.tmp"):
            # previous key found, decoding
            alert("Key found, starting decoding")
            self._key = _file("key.tmp", "rb")
        else:
            # no key found, generating new one
            self._key = _file("key.tmp", "wb")
            self.src = rand()
            self.gen_key()
            # I'm sorry. I'm so sorry...
            self._key.close()
            self._key = _file("key.tmp", "rb")
        self.process()

    def gen_key(self):
        # generate key of the same size as the input file
        alert("No key found, generating...")
        key = ""
        size = self._in.get_size()
        while size > 0:
            block = self.src.get_rand(min(self.block_size, size))
            key += block
            size = size - (len(block))
            self._key.write(bytes(key, 'UTF-8'))

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
            encrypted = ''.join([chr(data_in ^ data_out)
                                 for data_in, data_out in zip(data, key)])
            # writing in small chunks - bad for IO, but good for debugging
            self._out.write(bytes(encrypted, 'UTF-8'))


class _png(_file):
    # _file subclass with extra image handling

    crc_table = [None] * 256
    crc_table_computed = False
    has_key = False

    def __init__(self, fn, mode):
        self.fn = fn
        self.mode = mode
        self.fd = self.open()
        if not self.is_png():
            err(self.fn + " does not appear to be a PNG file")

    def is_png(self):
        # check the first eight bytes of a file to see if they match the
        # PNG signature
        header = self.read(8)
        self.reset_ptr()
        if header == None:
            err("No data in header")
        header_dec = []
        for dec in header:
            header_dec.append(dec)
        match = [137, 80, 78, 71, 13, 10, 26, 10]
        if header_dec == match:
            return True
        else:
            return False

    def put_key(self, _keyfile):
        # write key after IHDR chunk
        _keyfile.reset_ptr()
        key = _keyfile.read(_keyfile.get_size())
        injected = _file("injected.png", 'wb+')
        init = self.read(33)
        injected.write(init)
        chunk = self.create_chunk(key)
        injected.write(chunk)
        while 1:
            data = self.read(65535)
            if not data:
                break
            else:
                injected.write(data)

    def get_key(self):
        pass
        # _key = _file("key.tmp", "wb+")
        # self.reset_ptr()
        # self.move_ptr(33)
        # length = self.read(4)
        

    def create_chunk(self, data):
        # create a new chunk
        # consists of title, length, data and crc block
        title = "exTr"
        # size needs to be entered big-endian
        size = struct.pack('>I', len(data))
        chunk = title + data
        crc = struct.pack('I', self.gen_crc(chunk))
        return size + chunk + crc

    def gen_crc(self, chunk):
        # direct port of the sample implementation at
        # http://www.w3.org/TR/2003/REC-PNG-20031110/#D-CRCAppendix
        return self.update_crc(0xffffffff, chunk, len(chunk)) ^ 0xffffffff

    def make_crc_table(self):
        # create a quick lookup table for 8-byte values
        c = 0
        n = 0
        k = 0
        for n in range(256):
            c = n
            for k in range(8):
                if c & 1:
                    c = 0xedb88320 ^ (c >> 1)
                else:
                    c = c >> 1
            self.crc_table[n] = c
        self.crc_table_computed = True

    def update_crc(self, crc, buffer, length):
        # can't really remember how this works 
        # something something xor bitshift fiddlery
        c = crc
        n = 0
        if not self.crc_table_computed:
            self.make_crc_table()
        for n in range(length):
            c = self.crc_table[(c ^ ord(buffer[n])) & 0xff] ^ (c >> 8)
        return c


def test():
    try:
        args = get_args()
        #image = _png(args.image, "rb+")
        #image.get_key()
        crypto = crypt(args.infile, args.outfile)
        #if not image.has_key:
            #image.put_key(crypto._key)

    except KeyboardInterrupt:
        err("'Aborting")

test()
