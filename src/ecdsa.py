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

class ECDSAParamsP521(ECDSAParams):
    """
    Standard FIPS-186 : P521 curve
    """
    p = int('6864797660130609714981900799081393217269435300143305409394463459' \
            '1855431833976560521225596406614545549772963113914808580371219879' \
            '99716643812574028291115057151')
    order = int('686479766013060971498190079908139321726943530014330540939446' \
                '345918554318339765539424505774633321719753296399637136332111' \
                '3864768612440380340372808892707005449')
    a = (-3) % p
    b = int('051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10' \
            '9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503' \
            'f00', 16)
    gx = int('c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3' \
             'dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5' \
             'bd66', 16)
    gy = int('11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e' \
             '662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd' \
             '16650', 16)

    def __init__(self, h=hashlib.sha256):
        curve = ECC(self.__class__.a, self.__class__.b, self.__class__.p)
        g = curve.newPoint(self.__class__.gx, self.__class__.gy)
        ECDSAParams.__init__(self, curve, g, self.__class__.order, h)

if __name__ == '__main__':
    p521 = ECDSAParamsP521()
    (public, private) = p521.genKeys()

    s = private.sign(b"hello world")
    print(public.verify(s, b"hello world"))
