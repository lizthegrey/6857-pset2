#!/usr/bin/python2.6
# Copyright 2011 Google Inc. All Rights Reserved.
# Author: Liz Fong (lizf@google.com/lizfong@mit.edu)

"""Implements a set of methods for cracking the Bitdael cipher."""

import array
import cPickle
import itertools
import random
import urllib2


class BitDiddleModule(object):
  """Cracks Bitdael.

  Implements the core steps required to crack the Bitdael cipher with both two
  and three rounds, using analysis of ciphertext corresponding to chosen
  plaintexts.

  Requires 64 chosen plaintexts to determine an approximate guess for p.
  Requires 256 chosen plaintexts to determine S[0] (only for 3 rounds).
  Requires 256 chosen plaintexts to determine the full S table.
  Performs final checking with 256 random plaintexts.
  """

  def __init__(self):
    """Initializes a BitDiddleModule with parameters.

    rounds is the number of rounds to crack (either 2 or 3)
    local is a boolean indicating whether the real hw2 server should be used
      or instead a local (much faster) implementation of the cipher.
    """
    self.rounds = 3
    self.local = True

    if self.local:
      self.keymaster = BitDiddleLocalKeyMaster(self.rounds, True)
    else:
      self.keymaster = BitDiddleRemoteKeyMaster(self.rounds, True)
    self.p_guess = array.array("B", [0]*64)
    self.s_guess = array.array("B", [0]*256)

  def RunSerially(self):
    """Serially invokes each of the required steps to crack Bitdael."""
    # Compute an initial guess for p.
    p_initial = self.GuessP()
    print p_initial

    # Compute the offset if 3 rounds are involved; otherwise, offset=0
    if self.rounds == 3:
      offset = self.GuessOffset()
    else:
      offset = 0
    outputs = self.GuessS(p_initial, offset)

    # Save the output to make debugging easier.
    cPickle.dump([p_initial, outputs, offset, self.rounds],
                 open("guess.p", "wb"))

    # Serially enumerate the S tables for each byte.
    # This could be sharded by byte using a tool such as MapReduce.
    results = dict()
    for i in range(0, 8):
      for key, value in BitDiddleModule.Map(outputs, p_initial, i):
        # Emulate MapReduce"s "shuffle" function by aggregating outputs
        # that share the same key.
        immutable_key = tuple(key)
        try:
          results[immutable_key].append(value)
        except KeyError:
          results[immutable_key] = [value]

    # Checkpoint output to ease debugging.
    cPickle.dump(results, open("results.p", "wb"))

    # Save off our final results.
    for pair in results.items():
      result = BitDiddleModule.Reduce(pair[0], pair[1], p_initial)
      if result is not None:
        self.p_guess = result[0]
        self.s_guess = result[1]
        break

    # Check results against the keymaster.
    self.Check()

  def GuessP(self):
    """Attempts to guess p.

    Perturbs single bits in the plaintext and determines which corresponding
    byte in the ciphertext is altered in order to map values of p to the
    nearest byte.

    Returns:
      An array containing a guess for p.

    Raises:
      Exception: unable to find an output position for an input bit.
    """
    # Compute the reference ciphertext.
    zero_c = self.keymaster.GetCiphertext(0)

    # Set up data storage to populate as we find values.
    p_raw = [array.array("B", []) for i in range(0, 8)]
    p_guess = array.array("B", [0]*64)

    # Iterate over each bit in the half we"re controlling.
    for i in range(0, 64):
      c_bit = self.keymaster.GetCiphertext(
          BitDiddleUtil.ShiftIfThreeRounds(1 << i, self.rounds))
      # Compute the difference between the two ciphertexts.
      delta_l = (c_bit ^ zero_c) >> 64
      print "D: %s" % BitDiddleUtil.ToBase16(delta_l).zfill(16)

      # Find which byte changed.
      byte = BitDiddleUtil.GetNonZeroByte(delta_l)
      if byte == -1:
        # TODO(lizfong): deal with this case gracefully by evaluating a
        # different pair of original and disturbed plaintexts if altering a
        # bit of zero_c does not result in a change in output.
        raise Exception("Could not find byte position in p for input bit.")

      # Add the bit to the list of bits that affect the changed byte.
      p_raw[byte].append(i)
      print byte

    # Construct the provisional mapping from old bit to new bit.
    temp = [item for sublist in p_raw for item in sublist]
    print temp
    for i in range(0, 64):
      p_guess[i] = temp.index(i)

    return p_guess

  def GuessOffset(self):
    """Finds the ciphertexts for non-permuted sequences of repeated bytes.

    If any of them cancel out with S[0], producing 0 as the input to the
    next round and S[0] as the output of that round, we"ve found S[0].
    This only needs to be run for the three-round case.

    Returns:
      A 64-bit offset that must be XORed with future inputs.

    Raises:
      Exception: no candidate offsets found.
    """
    for value in range(0, 256):
      # Create the repeated value.
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value |= value << i
      # Encipher the repeated value, and find the output half to match.
      enc = self.keymaster.GetCiphertext(repeated_value << 64) >> 64
      if enc == repeated_value:
        # We"ve found the value of the S[0] offset.
        print "O: %s" % BitDiddleUtil.ToBase16(repeated_value).zfill(16)
        return repeated_value
    # If we"re unable to determine S, then we should stop execution.
    raise Exception("Could not find offset to accommodate s[0]")

  def GuessS(self, p_guess, offset):
    """Maps sequences of repeated single bytes through S.

    Uses the provisional guess for p to reverse-permute the bytes; this
    means that the derived values as inputs to S[x] will be some
    permutation of the bits of x that is different for each output byte; but
    is guaranteed to recover each possible input/output pair in some order.

    Args:
      p_guess: The provisional permutation table to use.
      offset: The computed offset to XOR all inputs with.

    Returns:
      A list of eight S'[x] truth tables.
    """
    # Set up a separate table for each byte position.
    outputs = [array.array("B", [0]*256) for i in range(0, 8)]

    # Iterate through each byte input value
    for value in range(0, 256):
      # Generate the repeated pattern e.g. 0xABABABABABABABAB for value 0xAB
      repeated_value = 0
      for i in range(0, 64, 8):
        repeated_value |= value << i
      # Reverse-permute the bits that we want to see after p to derive
      # appropriate initial input values.
      # If an offset exists, XOR the repeated pattern with the offset.
      cleartext = offset ^ BitDiddleUtil.Unpermute(repeated_value, p_guess)

      # Find the output of the cipher.
      enc = self.keymaster.GetCiphertext(
          BitDiddleUtil.ShiftIfThreeRounds(cleartext, self.rounds)) >> 64

      # Read each byte out of the cipher and encode it into the table
      # for the input value.
      for i in range(0, 8):
        output = (enc >> (i * 8)) & 0xFF
        outputs[i][value] = output

    return outputs

  def Map(outputs, i):
    """Enumerates permutations of an input byte to produce S[x]'s truth table.

    Args:
      outputs: For each byte, the s-table for that byte with an unknown byte
          permutation applied to that byte"s input value.
          e.g. S"[x] = S[pdelta[x]]
      i: The byte (0-indexed, lowest to highest) to generate permutations of.

    Yields:
      derived_s: The derived truth tables for S[x] (used as a reduce key).
      i: The input i
      p_delta: The permutation required to produce derived_s.
    """
    counter = 0
    for pdelta in itertools.permutations(
        array.array("B", [0, 1, 2, 3, 4, 5, 6, 7])):
      # This step is slow, since it iterates over ~40,000 permutations.
      # Output progress periodically so we know we aren"t stuck.
      if counter % 1000 == 0:
        print "%s: %s" % (i, counter)
      counter += 1

      derived_s = array.array("B", [0]*256)
      for x in range(0, 256):
        # Compute the new truth table by permuting the input byte.
        derived_s[BitDiddleUtil.Permute(x, pdelta)] = outputs[i][x]

      # We output the derived S truth table as the key, and the byte offset
      # of the inputs and the applied permutation as the value.
      yield derived_s, (i, pdelta)
  Map = staticmethod(Map)

  def Reduce(s_key, source_list, p_guess):
    """Acts on shuffled output and determines if a given derived S is valid.

    Validity means S can be derived from a permutation of each of the 8
    byte-position specific S" tables.

    Args:
      s_key: The S truth table (reduce key).
      source_list: A list of all byte positions and corresponding permutations
          which can be used to produce this S truth table.
      p_guess: The provisional guess for p.

    Returns:
      final_p: The final value of p to use.
      s_key: The S truth table to use.
    """
    # Stores the final set of offsets to use to generate this derived S.
    transform = []

    # Check at least one permutation leads to this S for each byte-position.
    found = [False]*8
    for offset in source_list:
      if found[offset[0]] != True:
        # We only need one entry for this byte; only append the first we see.
        transform.append(offset)
      found[offset[0]] = True
    success = True
    for value in found:
      if not value:
        success = False
        break
    if not success:
      return None

    # Compute the final value of p based on the valid offsets that we found.
    poffset = reduce(lambda x, y: x+list(y),  # pylint: disable-msg=C6402
                     [y[1] for y in transform], [])
    final_p = array.array("B", [0]*64)
    # Iterate through each start point 0-64.
    for i in range(0, 64):
      # The final value of any start point 0-64 is still within the same byte
      # thus 8 * (p_guess[i] / 8), but the bit position within the byte is
      # shifted. Bit p_guess[i] in the byte should actually be at the mapped
      # bit in poffset, thus poffset[p_guess[i]] within the byte.
      final_p[i] = 8 * (p_guess[i] / 8) + poffset[p_guess[i]]

    # Return both computed values.
    return (final_p, s_key)
  Reduce = staticmethod(Reduce)

  def Check(self):
    """Checks the result of the key computation for consistency."""

    # Do an initial sanity check using values we have already cached.
    if (BitDiddleUtil.EncryptLocally(
        0, self.p_guess, self.s_guess, self.rounds) ==
        self.keymaster.GetCiphertext(0)):
      print "Success!"
    # Check 256 additional random ciphertexts against the keymaster.
    for _ in range(0, 256):
      plaintext = random.randint(0, 2 ** 128 - 1)
      if (BitDiddleUtil.EncryptLocally(
          plaintext, self.p_guess, self.s_guess, self.rounds) !=
          self.keymaster.GetCiphertext(plaintext)):
        print "Failed on input %s" % plaintext
        break
    # Finally, submit the guess.
    self.keymaster.Guess(self.p_guess, self.s_guess)


class BitDiddleKeyMaster(object):
  """Abstract KeyMaster that encodes ciphertext and checks proposed answers."""

  def __init__(self, debug):
    self.ciphercache = dict()
    self.debug = debug

  def GetCiphertext(self, plaintext):
    """Retrieves the ciphertext corresponding to a given plaintext.

    Uses a cache to store previously encrypted values to avoid re-fetching.

    Args:
      plaintext: The plaintext to encrypt.

    Returns:
      The encrypted ciphertext corresponding to the plaintext.
    """
    try:
      return self.ciphercache[plaintext]
    except KeyError:
      request = BitDiddleUtil.ToBase16(plaintext).zfill(32)
      if self.debug:
        print "P: %s" % request
      ciphertext = self.CallKeymaster(request)
      if self.debug:
        print "C: %s" % ciphertext
      result = BitDiddleUtil.FromBase16(ciphertext)
      self.ciphercache[plaintext] = result
      return result


class BitDiddleLocalKeyMaster(BitDiddleKeyMaster):
  """Implements a fast local keymaster that reveals its keys upon guess."""

  def __init__(self, rounds, debug):
    BitDiddleKeyMaster.__init__(self, debug)

    self.p_actual = array.array("B", range(0, 64))
    random.shuffle(self.p_actual)
    self.s_actual = array.array("B", [random.randint(0, 255)
                                      for _ in range(0, 256)])
    self.rounds = rounds
    cPickle.dump([self.p_actual, self.s_actual], open("actual.p", "wb"))

  def CallKeymaster(self, plaintext):
    return BitDiddleUtil.ToBase16(BitDiddleUtil.EncryptLocally(
        BitDiddleUtil.FromBase16(plaintext),
        self.p_actual, self.s_actual, self.rounds)).zfill(32)

  def Guess(self, p, s):
    print "Guessed p: %s" % p
    print "Actual p:  %s" % self.p_actual
    print "Guessed s: %s" % str(s)
    print "Actual s:  %s" % self.s_actual


class BitDiddleRemoteKeyMaster(BitDiddleKeyMaster):
  """Talks to the remote keymaster on 6.857.scripts.mit.edu."""

  GROUP_NUM = 4
  GENKEY_URL = "http://6.857.scripts.mit.edu/ps2/genkey?team=%s&rounds=%s"
  ENC_URL = "http://6.857.scripts.mit.edu/ps2/encrypt?key=%s&data=%s"
  GUESS_URL = "http://6.857.scripts.mit.edu/ps2/guess?key=%s&p=%s&S=%s"

  def __init__(self, rounds, debug):
    BitDiddleKeyMaster.__init__(self, debug)

    genkey_url = self.__class__.GENKEY_URL % (self.__class__.GROUP_NUM,
                                              rounds)
    keynum = urllib2.urlopen(genkey_url).readline()
    self._key_number = int(keynum.split("b>")[1][0:-2])

  def CallKeymaster(self, plaintext):
    ciphertext = urllib2.urlopen(
        self.__class__.ENC_URL % (self._key_number, plaintext)).readline()
    return ciphertext

  def Guess(self, p, s):
    """Guesses the value of p and s."""
    print "Guessed p: %s" % p
    print "Guessed s: %s" % str(s)
    final_p = array.array("B", [0]*64)
    for i in range(0, 64):
      final_p[63 - i] = 63 - p.index(i)
    guess_final_url = self.__class__.GUESS_URL % (
        self._key_number,
        BitDiddleUtil.ArrayToBase16(final_p),
        BitDiddleUtil.ArrayToBase16(s))
    print guess_final_url
    print urllib2.urlopen(guess_final_url).readline()


class BitDiddleUtil(object):
  """Static utility methods used by BitDiddleModule and keymasters."""

  def ToBase16(num):
    """Converts a raw number into a hex value encoded as a string.

    Args:
      num: The number to convert.

    Returns:
      The hex value corresponding to num.
          Note that the hex value is not zero-padded.
          Callers should take care to always pad to the desired length.
    """
    return hex(num).rstrip("L").upper()[2:]
  ToBase16 = staticmethod(ToBase16)

  def FromBase16(base16):
    """Converts a hex value encoded as a string into an numeric value.

    Args:
      base16: The string to convert.

    Returns:
      The integer version of the base-16 contents of the string.
    """
    return int(base16, 16)
  FromBase16 = staticmethod(FromBase16)

  def ArrayToBase16(arr):
    """Unpacks an array of byte values into a string.

    Args:
      arr: An array of byte values.

    Returns:
      A continuous string of consecutive hex values for the bytes.
          Note that it is FIFO - first byte is leftmost.
    """
    resp = ""
    for value in arr:
      resp += BitDiddleUtil.ToBase16(value).zfill(2)
    return resp
  ArrayToBase16 = staticmethod(ArrayToBase16)

  def GetNonZeroByte(delta):
    """Returns the position of the first nonzero byte in a 64-bit number.

    Args:
      delta: A number encoding the XOR difference between two ciphertexts.

    Returns:
      Returns index of the first non-zero byte (read right to left, 0-indexed)
      Returns -1 if no such byte found.
    """
    i = 0
    while i < 8:
      if delta & 0xFF > 0:
        return i
      delta >>= 8
      i += 1
    return -1
  GetNonZeroByte = staticmethod(GetNonZeroByte)

  def ShiftIfThreeRounds(value, rounds):
    """Shifts the input 64-bit number by 64 bits if rounds = 3.

    This allows targeting the appropriate half of the input to be manipulated
    for differing number of rounds.

    Args:
      value: The value to possibly shift.
      rounds: The number of rounds used for this key-breaking attempt.

    Returns:
      Returns the original value if rounds = 3, otherwise rounds << 64.
    """
    if rounds == 3:
      return value << 64
    else:
      return value
  ShiftIfThreeRounds = staticmethod(ShiftIfThreeRounds)

  def EncryptLocally(plaintext, p, s, rounds):
    """A local implementation of the Bitdael algorithm.

    Args:
      plaintext: The 128-bit plaintext block.
      p: A permutation array that maps old bit positions to new bit positions.
      s: A substitution array that maps old bytes to new bytes.
      rounds: The number of rounds to perform.

    Returns:
      Returns the encrypted ciphertext.
    """
    result = plaintext
    for _ in range(0, rounds):
      result = BitDiddleUtil.Round(result, p, s)
    return result
  EncryptLocally = staticmethod(EncryptLocally)

  def Round(old_block, p, s):
    """Performs a single round of Bitdael.

    Args:
      old_block: The old block from the previous round/input.
      p: A permutation array that maps old bit positions to new bit positions.
      s: A substitution array that maps old bytes to new bytes.

    Returns:
      Returns the encrypted ciphertext from this round.
    """
    left = old_block >> 64
    right = old_block & 0xFFFFFFFFFFFFFFFF
    return ((right << 64) |
            (left ^ BitDiddleUtil.Substitute(BitDiddleUtil.Permute(right, p),
                                             s)))
  Round = staticmethod(Round)

  def Permute(half, p):
    """Performs the permutation step of Bitdael.

    For each input bit, looks up where in the output the bit should go and
    saves the bit.

    Args:
      half: The bits we would like to permute.
      p: A permutation array that maps old bit positions to new bit positions.

    Returns:
      Returns the permuted number.
    """
    scrambled = 0
    for bit in range(0, len(p)):
      scrambled |= (half & 1) << p[bit]
      half >>= 1
    return scrambled
  Permute = staticmethod(Permute)

  def Unpermute(half, p):
    """Reverses the permutation step of Bitdael.

    Args:
      half: The bits we would like to have produced following a Permute round.
      p: A permutation array that maps old bit positions to new bit positions.

    Returns:
      Returns the appropriate input required to produce the provided output.
    """
    scrambled = 0
    for bit in range(0, len(p)):
      scrambled |= (half & 1) << p.index(bit)
      half >>= 1
    return scrambled
  Unpermute = staticmethod(Unpermute)

  def Substitute(half, s):
    """Performs the substitution step of Bitdael.

    Replaces each input byte with a corresponding output byte from the
    substitution table.

    Args:
      half: The bytes that we would like to have substituted.
      s: A substitution array that maps old bytes to new bytes.

    Returns:
      Returns the substituted bytes.
    """
    scrambled = 0
    for byte in range(0, 64, 8):
      scrambled |= s[half & 0xFF] << byte
      half >>= 8
    return scrambled
  Substitute = staticmethod(Substitute)

if __name__ == "__main__":
  BitDiddleModule().RunSerially()
