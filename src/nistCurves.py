from ecdsa import *

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
