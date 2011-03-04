#!/usr/bin/python2.6

# Copyright (c) 2011 Google, Inc.
# Author: Liz Fong (lizf@google.com/lizfong@mit.edu)

import array
import cPickle
import itertools
import random
import urllib2

class BitDiddleModule:
  def __init__(self):
    self.p_guess = array.array('B', [0]*64)
    self.s_guess = array.array('B', [0]*256)
    self.rounds = 2
    #self.keymaster = BitDiddleLocalKeyMaster(self.rounds, True)
    self.keymaster = BitDiddleRemoteKeyMaster(self.rounds, True)

  def run(self):
    p_initial = self.guessP()
    print p_initial
    outputs = self.guessS(p_initial)

    # To be used in the future when I have separate compute nodes that need to use the pickles.
    cPickle.dump([p_initial, outputs, self.rounds], open("guess.p", "wb"))

    max_offset = 1

    if self.rounds == 3:
      # This will not actually work in any realistic time/memory single-threaded.
      # Provided only to make clear what the mapper/reducer are doing.
      max_offset = 256
    for k in range(0, max_offset):
      print 'k round is %s:' % k
      results = dict()
      for key, value in BitDiddleModule.mapper(outputs, p_initial, k):
        immutableKey = (key[0], tuple(key[1]))
        try:
          results[immutableKey].append(value)
        except KeyError:
          results[immutableKey] = [value]
      cPickle.dump(results, open("results_%s.p" % k, "wb"))
      (self.p_guess, self.s_guess) = BitDiddleModule.reduce(results, p_initial)
      if self.p_guess != None:
        break

    self.check()

  def guessP(self):
    # Map bits to bytes to find p
    zeroC = self.keymaster.getCiphertext(0)
    pRaw = [array.array('B', []) for i in range(0, 8)]
    p_guess = array.array('B', [0]*64)

    for i in range(0, 64):
      cBit = self.keymaster.getCiphertext(BitDiddleUtil.shiftIfThreeRounds(1 << i, self.rounds))
      deltaL = (cBit ^ zeroC) >> 64
      print 'D: %s' % BitDiddleUtil.toBase16(deltaL).zfill(16)
      byte = BitDiddleUtil.getNonZeroByte(deltaL)
      if byte == -1:
        # TODO(lizfong): deal with this case gracefully by evaluating a case that isn't comparing against zeroC.
        raise Exception('Could not find byte position in p for input bit.')
      pRaw[byte].append(i)
      print byte
    print pRaw
    temp = [item for sublist in pRaw for item in sublist]
    print temp
    for i in range(0, 64):
      p_guess[i] = temp.index(i)
    return p_guess

  def guessS(self, p_guess):
    # Map sequences of single bytes through S
    outputs = [array.array('B', [0]*256) for i in range(0, 8)]
    for value in range(0, 256):
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value = repeated_value | (value << i)
      enc = self.keymaster.getCiphertext(
        BitDiddleUtil.shiftIfThreeRounds(BitDiddleUtil.unpermute(repeated_value, p_guess), self.rounds)) >> 64

      for i in range(0, 8):
        output = (enc >> (i * 8)) & 0xFF
        outputs[i][value] = output

    return outputs

  def mapper(outputs, p_guess, k):
    # Now outputs contains, for each byte, the s-table for that byte with the byte permutation applied to that byte.
    # In the case of 2 rounds, I need to find a second-order permutation pdelta for each byte.
    # In the case of 3 rounds, I need to find both the second-order pdelta and an offset k.
    repeated_k = 0
    for i in range(0, 64, 8):
      repeated_k = repeated_k | (k << i)
    permuted_k = BitDiddleUtil.permute(repeated_k, p_guess)

    for i in range(0, 8):
      counter = 0
      for pdelta in itertools.permutations(array.array('B', [0, 1, 2, 3, 4, 5, 6, 7])):
        # Temp output progress
        if counter % 1000 == 0:
          print "%s: %s" % (i, counter)
        counter += 1

        s_temp = array.array('B', [0]*256)
        k_to_xor = permuted_k & 0xFF
        permuted_k = permuted_k >> 8

        for x in range(0, 256):
          s_temp[BitDiddleUtil.permute(x ^ k_to_xor, pdelta)] = outputs[i][x]
          
        yield (k, s_temp), (i, pdelta)
  mapper = staticmethod(mapper)

  def reduce(results, p_guess):
    for pair in results.items():
      output = BitDiddleModule.reduceInner(pair[0], pair[1], p_guess)
      if output != None:
        return output
      else:
        return (None, None)
  reduce = staticmethod(reduce)

  def reduceInner(sKey, sourceList, p_guess):
    transform = []

    found = [False]*8
    for offset in sourceList:
      if found[offset[0]] != True:
        # We only need one entry for this byte.
        transform.append(offset)
      found[offset[0]] = True
    success = True
    for value in found:
      if value == False:
        success = False
        break
    if not success:
      return None

    offset = reduce(lambda x, y: x+list(y), [y[1] for y in transform], [])
    final_p = array.array('B', [0]*64)
    for i in range(0, 64):
      final_p[i] = 8 * (p_guess[i] / 8) + offset[p_guess[i]]

    final_s = array.array('B', [0]*256)

    k = sKey[0]
    for i in range(0, 256):
      final_s[i] = sKey[1][i ^ k]

    return (final_p, final_s)
  reduceInner = staticmethod(reduceInner)

  def check(self):
    if BitDiddleUtil.encryptLocally(0, self.p_guess, self.s_guess, self.rounds) == self.keymaster.getCiphertext(0):
      print "Success!"
    for i in range(0, 256):
      plaintext = random.randint(0, 2 ** 128 - 1)
      if BitDiddleUtil.encryptLocally(plaintext, self.p_guess, self.s_guess, self.rounds) != self.keymaster.getCiphertext(plaintext):
        print "Failed on input %s" % plaintext
    self.keymaster.guess(self.p_guess, self.s_guess)

class BitDiddleKeyMaster:
  def __init__(self, debug):
    self.ciphercache = dict()
    self.debug = debug

  def getCiphertext(self, plaintext):
    try:
      return self.ciphercache[plaintext]
    except KeyError:
      request = BitDiddleUtil.toBase16(plaintext).zfill(32);
      if self.debug:
        print 'P: %s' % request
      ciphertext = self.callKeymaster(request)
      if self.debug:
        print 'C: %s' % ciphertext
      result = BitDiddleUtil.fromBase16(ciphertext)
      self.ciphercache[plaintext] = result
      return result

class BitDiddleLocalKeyMaster(BitDiddleKeyMaster):
  def __init__(self, rounds, debug):
    BitDiddleKeyMaster.__init__(self, debug)

    self.p_actual = array.array('B', range(0, 64))
    random.shuffle(self.p_actual)
    self.s_actual = array.array('B', [random.randint(0, 255) for x in range(0, 256)])
    self.rounds = rounds
    cPickle.dump([self.p_actual, self.s_actual], open("actual.p", "wb"))

  def callKeymaster(self, plaintext):
    return BitDiddleUtil.toBase16(BitDiddleUtil.encryptLocally(BitDiddleUtil.fromBase16(plaintext), self.p_actual, self.s_actual, self.rounds)).zfill(32)

  def guess(self, p, s):
    print 'Guessed p: %s' % p
    print 'Actual p:  %s' % self.p_actual
    print 'Guessed s: %s' % str(s)
    print 'Actual s:  %s' % self.s_actual

class BitDiddleRemoteKeyMaster(BitDiddleKeyMaster):
  def __init__(self, rounds, debug):
    BitDiddleKeyMaster.__init__(self, debug)

    self.GROUP_NUM = 4
    self.GENKEY_URL = (
      'http://6.857.scripts.mit.edu/ps2/genkey?team=%s&rounds=%s' % (self.GROUP_NUM, rounds))
    self.ENC_URL = 'http://6.857.scripts.mit.edu/ps2/encrypt?key=%s&data=%s'
    self.GUESS_URL = 'http://6.857.scripts.mit.edu/ps2/guess?key=%s&p=%s&S=%s'

    keynum = urllib2.urlopen(self.GENKEY_URL).readline()
    self.KEY_NUMBER = int(keynum.split('b>')[1][0:-2])

  def callKeymaster(self, plaintext):
    ciphertext = urllib2.urlopen(self.ENC_URL % (self.KEY_NUMBER, plaintext)).readline()
    return ciphertext

  def guess(self, p, s):
    print 'Guessed p: %s' % p
    print 'Guessed s: %s' % str(s)
    final_p = array.array('B', [0]*64)
    for i in range(0, 64):
      final_p[63 - i] = 63 - p.index(i)
    guess_final_url =  self.GUESS_URL % (self.KEY_NUMBER, BitDiddleUtil.arrayToBase16(final_p), BitDiddleUtil.arrayToBase16(s))
    print guess_final_url
    print urllib2.urlopen(guess_final_url).readline()

class BitDiddleUtil:
  def toBase16(num):
    return hex(num).rstrip('L').upper()[2:]
  toBase16 = staticmethod(toBase16)

  def fromBase16(base16):
    return int(base16, 16)
  fromBase16 = staticmethod(fromBase16)

  def arrayToBase16(arr):
    resp = ''
    for value in arr:
      resp += BitDiddleUtil.toBase16(value).zfill(2)
    return resp
  arrayToBase16 = staticmethod(arrayToBase16)

  def getNonZeroByte(delta):
    i = 0
    while i < 8:
      if delta & 0xFF > 0:
        return i
      delta = delta >> 8
      i += 1
    return -1
  getNonZeroByte = staticmethod(getNonZeroByte)

  def shiftIfThreeRounds(value, rounds):
    if rounds == 3:
      return value << 64
    else:
      return value
  shiftIfThreeRounds = staticmethod(shiftIfThreeRounds)

  def encryptLocally(plaintext, p, s, rounds):
    result = plaintext
    for i in range(0, rounds):
      result = BitDiddleUtil.round(result, p, s)
    return result
  encryptLocally = staticmethod(encryptLocally)

  def round(plaintext, p, s):
    left = plaintext >> 64
    right = plaintext & 0xFFFFFFFFFFFFFFFF
    return (right << 64) | (left ^ BitDiddleUtil.substitute(BitDiddleUtil.permute(right, p), s))
  round = staticmethod(round)

  def permute(half, p):
    scrambled = 0
    for bit in range(0, len(p)):
      scrambled = scrambled | ((half & 1) << p[bit])
      half = half >> 1
    return scrambled
  permute = staticmethod(permute)

  def unpermute(bytes, p):
    scrambled = 0
    for bit in range(0, len(p)):
      scrambled = scrambled | ((bytes & 1) << p.index(bit))
      bytes = bytes >> 1
    return scrambled
  unpermute = staticmethod(unpermute)

  def substitute(half, s):
    scrambled = 0
    for byte in range(0, 64, 8):
      scrambled = scrambled | (s[half & 0xFF] << byte)
      half = half >> 8
    return scrambled
  substitute = staticmethod(substitute)

if __name__ == '__main__':
  BitDiddleModule().run()
