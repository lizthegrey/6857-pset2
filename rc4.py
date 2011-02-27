#!/usr/bin/env python

import secrets

def rc4(key, k, l):
    jbits = ""
    stream = ""

    mask = (2**k - 1) << (8 - k)

    i = j = 0
    S = range(256)
    for i in xrange(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        (S[i], S[j]) = (S[j], S[i])

    i = j = 0
    for n in xrange(l):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        (S[i], S[j]) = (S[j], S[i])
        jbits += chr(j & mask)
        stream += chr(S[(S[i] + S[j]) % 256])

    return (jbits, stream)

if __name__ == '__main__':
    for k in xrange(8):
        (jbits, stream) = rc4(secrets.secrets[k], k+1, 2**20)
        open("jbits%d.dat" % (k+1), "w").write(jbits)
        open("stream%d.dat" % (k+1), "w").write(stream)
