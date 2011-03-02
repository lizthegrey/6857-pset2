#!/usr/bin/python

import random
import cPickle
import itertools

class BitDiddleBreaker:
  def __init__(self):
    self.ciphercache = dict()
    self.rounds = 2
    self.p_guess = [0]*64
    self.s_guess = [0]*256
    self.p_actual = range(0, 64)
    random.shuffle(self.p_actual)
    self.s_actual = [random.randint(0, 255) for x in range(0, 256)]

  def getCiphertext(self, plaintext):
     try:
       return self.ciphercache[plaintext]
     except KeyError:
       request = self.toBase16(plaintext).zfill(32);
       print 'P: %s' % request
       ciphertext = self.toBase16(self.encryptLocally(plaintext, self.p_actual, self.s_actual, self.rounds)).zfill(32)
       print 'C: %s' % ciphertext
       result = self.fromBase16(ciphertext)
       self.ciphercache[plaintext] = result
       return result

  def guess(self):
    print self.p_guess
    print self.p_actual
    print self.s_guess
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

  def shiftIfThreeRounds(self, value):
    if self.rounds == 3:
      return value << 64
    else:
      return value

  def unpermute(self, bytes, p):
    scrambled = 0
    for bit in range(0, len(p)):
      scrambled = scrambled | ((bytes & 1) << p.index(bit))
      bytes = bytes >> 1
    return scrambled

  def encryptLocally(self, plaintext, p, s, rounds):
    result = plaintext
    for i in range(0, rounds):
      result = self.round(result, p, s)
    return result

  def round(self, plaintext, p, s):
    left = plaintext >> 64
    right = plaintext & 0xFFFFFFFFFFFFFFFF
    return (right << 64) | (left ^ self.substitute(self.permute(right, p), s))

  def permute(self, half, p):
    scrambled = 0
    for bit in range(0, len(p)):
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
    pRaw = [[], [], [], [], [], [], [], []]

    for i in range(0, 64):
      cBit = self.getCiphertext(self.shiftIfThreeRounds(1 << i))
      deltaL = (cBit ^ zeroC) >> 64
      print 'D: %s' % self.toBase16(deltaL).zfill(16)
      byte = self.getNonZeroByte(deltaL)
      if byte == -1:
        return
      pRaw[byte].append(i)
      print byte
    print pRaw
    temp = [item for sublist in pRaw for item in sublist]
    print temp
    for i in range(0, 64):
      self.p_guess[i] = temp.index(i)
    print self.p_guess

    # Map sequences of single bytes through S
    outputs = [[0]*256 for i in range(0, 8)]
    for value in range(0, 256):
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value = repeated_value | (value << i)
      enc = self.getCiphertext(
        self.shiftIfThreeRounds(self.unpermute(repeated_value, self.p_guess))) >> 64

      for i in range(0, 8):
        output = (enc >> (i * 8)) & 0xFF
        outputs[i][value] = output

    # To be used in the future when I have separate compute nodes that need to use the pickles.
    cPickle.dump([self.p_guess, outputs, self.rounds], open("guess.p", "wb"))
    cPickle.dump([self.p_actual, self.s_actual, self.rounds], open("actual.p", "wb"))

    # Now outputs contains, for each byte, the s-table for that byte with the byte permutation applied to that byte.
    # In the case of 2 rounds, I need to find a second-order permutation pdelta for each byte.
    results = dict()
    for i in range(0, 8):
      counter = 0
      for pdelta in itertools.permutations([0, 1, 2, 3, 4, 5, 6, 7]):
        # Temp output progress
        if counter % 1000 == 0:
          print "%s: %s" % (i, counter)
        counter += 1

        s_temp = [0]*256
        for x in range(0, 256):
          s_temp[self.permute(x, pdelta)] = outputs[i][x]
        try:
          results[tuple(s_temp)].append((i, pdelta))
        except KeyError:
          results[tuple(s_temp)] = [(i, pdelta)]

    cPickle.dump(results, open("results.p", "wb"))

    for key in results:
      found = [False]*8
      for offset in results[key]:
        found[offset[0]] = True
      success = True
      for value in found:
        if value == False:
          success = False
          break
      if success:
        self.s_guess = key
        transform = results[key]
        break

    offset = reduce(lambda x, y: x+list(y), [y[1] for y in transform], [])
    final = [0]*64
    for i in range(0, 64):
      final[i] = 8*(self.p_guess[i]/8)+offset[self.p_guess[i]]

    self.p_guess = final

    if self.encryptLocally(0, self.p_guess, self.s_guess, self.rounds) == zeroC:
      print "Success!"
    self.guess()

if __name__ == '__main__':
  BitDiddleBreaker().run()
