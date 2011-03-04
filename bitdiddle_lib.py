#!/usr/bin/python2.6

# Copyright (c) 2011 Google, Inc.
# Author: Liz Fong (lizf@google.com/lizfong@mit.edu)

import array
import cPickle
import itertools
import random
import urllib2

class BitDiddleModule:
'''
  Implements the core steps required to crack the BitDiddle cipher with both
  two and three rounds, using analysis of ciphertext corresponding to chosen
  plaintexts.

  Requires 64 chosen plaintexts to determine an approximate guess for p.
  Requires 256 chosen plaintexts to determine S[0] (only applies to 3 rounds).
  Requires 256 chosen plaintexts to determine the full S table.
  Performs final checking with 256 random plaintexts.
'''

  def __init__(self):
    '''
      Initializes a BitDiddleModule with parameters.
      rounds is the number of rounds to crack (either 2 or 3)
      local is a boolean indicating whether the real hw2 server should be used
        or instead a local (much faster) implementation of the cipher.
    '''
    self.rounds = 3
    self.local = False

    if self.local:
      self.keymaster = BitDiddleLocalKeyMaster(self.rounds, True)
    else:
      self.keymaster = BitDiddleRemoteKeyMaster(self.rounds, True)
    self.p_guess = array.array('B', [0]*64)
    self.s_guess = array.array('B', [0]*256)

  def runSerially(self):
    '''
      Serially invokes each of the required steps to crack BitDiddle.
    '''
    # Compute an initial guess for p.
    p_initial = self.guessP()
    print p_initial

    # Compute the offset if 3 rounds are involved; otherwise, offset=0
    if self.rounds == 3:
      offset = self.guessOffset()
    else:
      offset = 0
    outputs = self.guessS(p_initial, offset)

    # Save the output to make debugging easier.
    cPickle.dump([p_initial, outputs, offset, self.rounds],
                 open('guess.p', 'wb'))

    # Serially enumerate the S tables for each byte.
    # This could be sharded by byte using a tool such as MapReduce.
    results = dict()
    for i in range(0, 8):
      for key, value in BitDiddleModule.mapper(outputs, p_initial, i):
        # Emulate MapReduce's "shuffle" function by aggregating outputs
        # that share the same key.
        immutableKey = tuple(key)
        try:
          results[immutableKey].append(value)
        except KeyError:
          results[immutableKey] = [value]

    # Checkpoint output to ease debugging.
    cPickle.dump(results, open('results.p', 'wb'))

    # Save off our final results.
    (self.p_guess, self.s_guess) = BitDiddleModule.reduce(results, p_initial)

    # Check results against the keymaster.
    self.check()

  def guessP(self):
    '''
      Perturbs single bits in the plaintext and determines which corresponding
      byte in the ciphertext is altered in order to map values of p to the
      nearest byte.
    '''
    # Compute the reference ciphertext.
    zeroC = self.keymaster.getCiphertext(0)

    # Set up data storage to populate as we find values.
    pRaw = [array.array('B', []) for i in range(0, 8)]
    p_guess = array.array('B', [0]*64)

    # Iterate over each bit in the half we're controlling.
    for i in range(0, 64):
      cBit = self.keymaster.getCiphertext(
        BitDiddleUtil.shiftIfThreeRounds(1 << i, self.rounds))
      # Compute the difference between the two ciphertexts.
      deltaL = (cBit ^ zeroC) >> 64
      print 'D: %s' % BitDiddleUtil.toBase16(deltaL).zfill(16)

      # Find which byte changed.
      byte = BitDiddleUtil.getNonZeroByte(deltaL)
      if byte == -1:
        # TODO(lizfong): deal with this case gracefully by evaluating a
        # different pair of original and disturbed plaintexts if altering a
        # bit of zeroC does not result in a change in output.
        raise Exception('Could not find byte position in p for input bit.')

      # Add the bit to the list of bits that affect the changed byte.
      pRaw[byte].append(i)
      print byte

    # Construct the provisional mapping from old bit to new bit.
    temp = [item for sublist in pRaw for item in sublist]
    print temp
    for i in range(0, 64):
      p_guess[i] = temp.index(i)

    return p_guess

  def guessOffset(self):
    '''
      Find the ciphertexts for non-permuted sequences of repeated bytes.
      If any of them cancel out with S[0], producing 0 as the input to the
      next round and S[0] as the output of that round, we've found S[0].
      This only needs to be run for the three-round case.
    '''
    for value in range(0, 256):
      # Create the repeated value.
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value = repeated_value | (value << i)
      # Encipher the repeated value, and find the output half to match.
      enc = self.keymaster.getCiphertext(repeated_value << 64) >> 64
      if enc == repeated_value:
        # We've found the value of the S[0] offset.
        print 'O: %s' % BitDiddleUtil.toBase16(repeated_value).zfill(16)
        return repeated_value
    # If we're unable to determine S, then we should stop execution.
    raise Exception('Could not find offset to accommodate s[0]')

  def guessS(self, p_guess, offset):
    '''
      Map sequences of repeated single bytes through S using the provisional
      guess for p to reverse-permute the bytes; this means that the derived
      values as inputs to S[x] will be some permutation of the bits of x
      that is different for each output byte; but is guaranteed to recover
      each possible input/output pair in some order.
    '''
    # Set up a separate table for each byte position.
    outputs = [array.array('B', [0]*256) for i in range(0, 8)]

    # Iterate through each byte input value
    for value in range(0, 256):
      # Generate the repeated pattern e.g. 0xABABABABABABABAB for value 0xAB
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value = repeated_value | (value << i)
      # Reverse-permute the bits that we want to see after p to derive
      # appropriate initial input values.
      # If an offset exists, XOR the repeated pattern with the offset.
      cleartext = offset ^ BitDiddleUtil.unpermute(repeated_value, p_guess)

      # Find the output of the cipher.
      enc = self.keymaster.getCiphertext(
        BitDiddleUtil.shiftIfThreeRounds(cleartext, self.rounds)) >> 64

      # Read each byte out of the cipher and encode it into the table
      # for the input value.
      for i in range(0, 8):
        output = (enc >> (i * 8)) & 0xFF
        outputs[i][value] = output

    return outputs

  def mapper(outputs, p_guess, i):
    '''
      Outputs contains, for each byte, the s-table for that byte with an
      unknown byte permutation applied to that byte's input value.
      e.g. S'[x] = S[pdelta[x]]
      Enumerate each possible byte permutation of the input byte to produce
      a possible truth table for the original S[x].
    '''
    counter = 0
    for pdelta in itertools.permutations(array.array('B', [0, 1, 2, 3, 4, 5, 6, 7])):
      # This step is slow, since it iterates over ~40,000 permutations.
      # Output progress periodically so we know we aren't stuck.
      if counter % 1000 == 0:
        print '%s: %s' % (i, counter)
      counter += 1

      derived_s = array.array('B', [0]*256)
      for x in range(0, 256):
        # Compute the new truth table by permuting the input byte.
        derived_s[BitDiddleUtil.permute(x, pdelta)] = outputs[i][x]

      # We output the derived S truth table as the key, and the byte offset
      # of the inputs and the applied permutation as the value.
      yield derived_s, (i, pdelta)
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

    return (final_p, sKey)
  reduceInner = staticmethod(reduceInner)

  def check(self):
    if BitDiddleUtil.encryptLocally(0, self.p_guess, self.s_guess, self.rounds) == self.keymaster.getCiphertext(0):
      print 'Success!'
    for i in range(0, 256):
      plaintext = random.randint(0, 2 ** 128 - 1)
      if BitDiddleUtil.encryptLocally(plaintext, self.p_guess, self.s_guess, self.rounds) != self.keymaster.getCiphertext(plaintext):
        print 'Failed on input %s' % plaintext
        break
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
    cPickle.dump([self.p_actual, self.s_actual], open('actual.p', 'wb'))

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
  BitDiddleModule().runSerially()
