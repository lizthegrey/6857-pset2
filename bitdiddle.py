#!/usr/bin/python

import urllib2


class BitDiddleBreaker:
  def __init__(self):
    self.GROUP_NUM = 4
    self.GENKEY_URL = (
      'http://6.857.scripts.mit.edu/ps2/genkey?team=%s&rounds=3' % self.GROUP_NUM)
    self.ENC_URL = 'http://6.857.scripts.mit.edu/ps2/encrypt?key=%s&data=%s'
    self.GUESS_URL = 'http://6.857.scripts.mit.edu/ps2/guess?key=%s&p=%s&S=%s'
    self.ciphercache = dict()
    self.pRaw = [[], [], [], [], [], [], [], []]
    self.p = []
    self.s = [0]*256

  def getNewKey(self):
    text = urllib2.urlopen(self.GENKEY_URL).readline()
    self.KEY_NUMBER = int(text.split('b>')[1][0:-2])

  def getCiphertext(self, plaintext):
     try:
       return self.ciphercache[plaintext]
     except KeyError:
       request = self.toBase16(plaintext).zfill(32);
       print 'P: %s' % request
       ciphertext = urllib2.urlopen(
         self.ENC_URL % (self.KEY_NUMBER, request)).readline()
       print 'C: %s' % ciphertext
       result = self.fromBase16(ciphertext)
       self.ciphercache[plaintext] = result
       return result

  def guess(self, p, s):
    print self.GUESS_URL % (self.KEY_NUMBER, self.arrayToBase16(p), self.arrayToBase16(s))
    return urllib2.urlopen(
        self.GUESS_URL % (self.KEY_NUMBER, self.arrayToBase16(p), self.arrayToBase16(s))
      ).readline()

  def toBase16(self, num):
    return hex(num).rstrip('L').upper()[2:]

  def fromBase16(self, base16):
    return int(base16, 16)

  def arrayToBase16(self, arr):
    resp = ''
    for value in arr:
      resp += self.toBase16(value).zfill(2)
    return resp

  def getNonZeroByte(self, delta):
    i = 0
    while i < 8:
      if delta & 0xFF > 0:
        return i
      delta = delta >> 8
      i += 1
    return -1

  def encodeBytes(self, bytes):
    result = 0
    scrambled = 0
    for byte in bytes:
      result = result << 8
      result = result | byte
    for bit in range(0, 64):
      scrambled = scrambled | ((result & 1) << self.p.index(bit))
      result = result >> 1
    return scrambled

  def run(self):
    self.getNewKey()

    # Map bits to bytes to find p
    zeroC = self.getCiphertext(0)
    for i in range(64, 128):
      cBit = self.getCiphertext(2 ** i)
      deltaL = (cBit ^ zeroC) >> 64
      print 'D: %s' % self.toBase16(deltaL).zfill(16)
      byte = self.getNonZeroByte(deltaL)
      if byte == -1:
        return
      self.pRaw[byte].append(i - 64)
      print byte
    print self.pRaw
    self.p = [item for sublist in self.pRaw for item in sublist]
    print self.p

    # Map sequences of single bytes through S
    outputs = dict()
    candidatesForS0 = []
    for value in range (0, 256, 8):
      enc = self.getCiphertext(
        self.encodeBytes([value + 7, value + 6, value + 5, value + 4, value + 3, value + 2, value + 1, value]) << 64)
      for i in range(0, 8):
        output = enc & 0xFF
        outputs[value + i] = output
        enc = enc >> 8
        if (output == value + i):
          candidatesForS0.append(output)
    print candidatesForS0

    if len(candidatesForS0) != 1:
      return

    for i in range(0, 256):
      self.s[i ^ candidatesForS0[0]] = outputs[i]

    print self.s

    print self.guess(self.p, self.s)

if __name__ == '__main__':
  BitDiddleBreaker().run()
