from ecc import ECC, ECCPoint, ECCInfinitePoint
from utils import *
import hashlib

class ECDSAPrivateKey:
    """
    Representation of the private key.
    Attributes:
          params: public parameters (curve, order, generator...)
          d: the private multiplier
    """
    def __init__(self, params, d):
        assert isinstance(params, ECDSAParams)

        if d <= 0 or d >= params.order:
            raise Exception("Invalid private key !")

        self.__params = params
        self.__d = d

    @property
    def params(self):
        return self.__params

    def sign(self, m, k=None):
        """ Sign a message using ECDSA algorithm """
        hash_fct = self.params.hashFunc
        order = self.params.order
        generator = self.params.generator

        (x, y) = (0, 0)

        while x == 0 or y == 0:
            if k is None:
                k = randomIntegerUnbias(order)
            k_inv = invMod(k, order)
            p = k * generator
            x = p.x % order
            h = hashMessage(hash_fct, m, order)

            y = k_inv * ((h + self.__d * x) % order)
            y %= order

        return ECDSASignature(self.params, x, y)

class ECDSAPublicKey:
    """
    Representation of the public key
    Attributes:
         params: public parameters (curve, order, generator...)
         p: the public point [k]G
    """
    def __init__(self, params, p):
        assert isinstance(params, ECDSAParams)
        assert isinstance(p, ECCPoint)

        if p.curve != params.curve:
            raise Exception("Not the same curve !")

        if p.isInfinity():
            raise Exception("Invalid public point !")

        self.__params = params
        self.__p = p

    @property
    def params(self):
        return self.__params

    @property
    def p(self):
        return self.__p

    def verify(self, sign, m):
        """ Verify an ECDSA signature """

        hash_fct = self.params.hashFunc
        g = self.params.generator
        order = self.params.order

        y_inv = invMod(sign.s, order)
        h = hashMessage(hash_fct, m, order)
        v1 = (h * y_inv) % order
        v2 = (sign.r * y_inv) % order
        p =  v1 * g + v2 * self.p

        return sign.r % order == p.x % order

class ECDSASignature:
    """
    Representation an ECDSA signature.
    Attributes:
          params: the public parameters associed to the signature
          (x,y): the signature
    """
    def __init__(self, params, r, s):
        self.r = r
        self.s = s
        self.params = params

    def __repr__(self):
        """ String representation of a signature """
        return "(%d, %d)" % (self.r, self.s)

class ECDSAParams:
    """
    ECDSA public parameters.
    Attributes:
          curve: the ECC curve to use
          generator: the ECCPoint used as generator
          order: the order of the generator, i.e order * generator = 0
          h: the hash function used for signature
    """
    def __init__(self, curve, generator, order, h=hashlib.sha256):
        assert isinstance(curve, ECC)
        assert isinstance(generator, ECCPoint)

        if generator.isInfinity():
            raise Exception("Generator can't be infinite point !")

        if not generator.isOnCurve():
            raise Exception("Generator isn't on the curve !")

        if not isPrime(order):
            raise Exception("Generator order must be prime !")

        if (order * generator) != curve.newInfinitePoint():
            raise Exception("Bad order for the generator !")

        self.__curve = curve
        self.__order = order
        self.__generator = generator
        self.__hash_fct = h

    @property
    def curve(self):
        return self.__curve

    @property
    def order(self):
        return self.__order

    @property
    def generator(self):
        return self.__generator

    @property
    def hashFunc(self):
        return self.__hash_fct

    def genKeys(self):
        """ Generate public and private key pairs """
        k = randomIntegerUnbias(self.order)
        public = ECDSAPublicKey(self, k * self.generator)
        private = ECDSAPrivateKey(self, k)

        return (public, private)
