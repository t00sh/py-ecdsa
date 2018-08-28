"""
Utilities functions for modular arithmetic, generating random integers...
"""

from random import randint
import os

def randomInteger(numBytes):
    """ Generate a cryptographic secure integer, 0 <= r < 2**8*numBytes """
    assert numBytes > 0
    r = os.urandom(numBytes)
    return int(r.hex(), 16)

def randomIntegerUnbias(n):
    """ Return an integer between 1 and n-1 without any potential biais"""
    assert n > 1
    nbytes = n.bit_length() // 8 + 1
    r = randomInteger(nbytes)
    while r > n - 2:
        r = randomInteger(nbytes)
    return r + 1


def xgcd(a, b):
    """ Extended Enclide Algorithm """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, y0, x0

def invMod(a, n):
    """ Return the modular inverse of a (mod n) """
    (g, u, v) = xgcd(a % n, n)
    if g != 1:
        raise Exception("Can't find modular inverse : gcd(%d,%d) != 1" % (a, n))
    return u%n

def isPrime(n, k=64):
    """ Miller-Rabin primality test """
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        x = pow(randint(2, n-1), d, n)
        if x == 1 or x == n-1:
            continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1:
                return False
            if x == n-1:
                break
        else:
            return False
    return True
