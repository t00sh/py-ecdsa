from ecc import ECC, ECCPoint, ECCInfinitePoint
from utils import isPrime, randomIntegerUnbias, invMod
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

        self.params = params
        self.d = d

    def sign(self, m, nonce=None):
        """ Sign a message using ECDSA algorithm """
        hash_fct = self.params.hash_fct
        (x, y) = (0, 0)

        while x == 0 or y == 0:
            if nonce is not None:
                k = nonce
            else:
                k = randomIntegerUnbias(self.params.order)
            k_inv = invMod(k, self.params.order)
            p = k * self.params.generator
            x = p.x % self.params.order
            y = k_inv * (int(hash_fct(m).hexdigest(), 16) + self.d * x)
            y %= self.params.order

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

        self.params = params
        self.p = p

    def verify(self, sign, m):
        """ Verify an ECDSA signature """

        hash_fct = self.params.hash_fct
        g = self.params.generator
        order = self.params.order
        y_inv = invMod(sign.s, order)
        v1 = (int(hash_fct(m).hexdigest(), 16) * y_inv) % order
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

        self.curve = curve
        self.order = order
        self.generator = generator
        self.hash_fct = h

    def genKeys(self):
        """ Generate public and private key pairs """
        k = randomIntegerUnbias(self.order)
        public = ECDSAPublicKey(self, k * self.generator)
        private = ECDSAPrivateKey(self, k)

        return (public, private)
