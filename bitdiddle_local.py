#!/usr/bin/python

import random

class BitDiddleBreaker:
  def __init__(self):
    self.ciphercache = dict()
    self.pRaw = [[], [], [], [], [], [], [], []]
    self.p = []
    self.s = [0]*256
    self.p_actual = range(0, 64)
    random.shuffle(self.p_actual)
    self.s_actual = [random.randint(0, 256) for x in range(0, 256)]

  def getCiphertext(self, plaintext):
     try:
       return self.ciphercache[plaintext]
     except KeyError:
       request = self.toBase16(plaintext).zfill(32);
       print 'P: %s' % request
       ciphertext = self.toBase16(self.encryptLocally(plaintext, self.p_actual, self.s_actual)).zfill(32)
       print 'C: %s' % ciphertext
       result = self.fromBase16(ciphertext)
       self.ciphercache[plaintext] = result
       return result

  def guess(self, p, s):
    print self.p
    print self.p_actual
    print self.s
    print self.s_actual

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

  def encryptLocally(self, plaintext, p, s):
    result = plaintext
    for i in range(0, 3):
      result = self.round(result, p, s)
    return result

  def round(self, plaintext, p, s):
    left = plaintext >> 64
    right = plaintext & 0xFFFFFFFFFFFFFFFF
    return (right << 64) | (left ^ self.substitute(self.permute(right, p), s))

  def permute(self, half, p):
    scrambled = 0
    for bit in range(0, 64):
      scrambled = scrambled | ((half & 1) << p[bit])
      half = half >> 1
    return scrambled

  def substitute(self, half, s):
    scrambled = 0
    for byte in range(0, 64, 8):
      scrambled = scrambled | (s[half & 0xFF] << byte)
      half = half >> 8
    return scrambled

  def run(self):
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
        self.encodeBytes([value + 7, value + 6, value + 5, value + 4, value + 3, value + 2, value + 1, value]) << 64) >> 64
      for i in range(0, 8):
        output = enc & 0xFF
        outputs[value + i] = output
        enc = enc >> 8
        if (output == value + i):
          candidatesForS0.append(output)
    print candidatesForS0

    for candidate in candidatesForS0:
      for i in range(0, 256):
        self.s[i] = outputs[i ^ candidate]
      print self.s

#      if self.encryptLocally(0, self.p, self.s) == zeroC:
      print self.guess(self.p, self.s)

if __name__ == '__main__':
  BitDiddleBreaker().run()
