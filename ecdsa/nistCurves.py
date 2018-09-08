from .ecdsaAlgo import *

class ECDSAParamsP192(ECDSAParams):
    """
    Standard FIPS-186 : P192 curve
    """
    p = int('6277101735386680763835789423207666416083908700390324961279')
    order = int('6277101735386680763835789423176059013767194773182842284081')
    a = (-3) % p
    b = int('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16)
    gx = int('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012', 16)
    gy = int('07192b95ffc8da78631011ed6b24cdd573f977a11e794811', 16)

    def __init__(self, h=hashlib.sha256):
        curve = ECC(self.__class__.a, self.__class__.b, self.__class__.p)
        g = curve.newPoint(self.__class__.gx, self.__class__.gy)
        ECDSAParams.__init__(self, curve, g, self.__class__.order, h)

class ECDSAParamsP224(ECDSAParams):
    """
    Standard FIPS-186 : P224 curve
    """
    p = int('2695994666715063979466701508701963067355791626002630814351' \
            '0066298881')
    order = int('269599466671506397946670150870196259404578077144243917' \
                '21682722368061')
    a = (-3) % p
    b = int('b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4', 16)
    gx = int('b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21', 16)
    gy = int('bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34', 16)

    def __init__(self, h=hashlib.sha256):
        curve = ECC(self.__class__.a, self.__class__.b, self.__class__.p)
        g = curve.newPoint(self.__class__.gx, self.__class__.gy)
        ECDSAParams.__init__(self, curve, g, self.__class__.order, h)

class ECDSAParamsP256(ECDSAParams):
    """
    Standard FIPS-186 : P256 curve
    """
    p = int('115792089210356248762697446949407573530086143415290314195' \
            '533631308867097853951')
    order = int('11579208921035624876269744694940757352999695522413576' \
                '0342422259061068512044369')
    a = (-3) % p
    b = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e2' \
            '7d2604b', 16)
    gx = int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945' \
             'd898c296', 16)
    gy = int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb64068' \
             '37bf51f5', 16)

    def __init__(self, h=hashlib.sha256):
        curve = ECC(self.__class__.a, self.__class__.b, self.__class__.p)
        g = curve.newPoint(self.__class__.gx, self.__class__.gy)
        ECDSAParams.__init__(self, curve, g, self.__class__.order, h)

class ECDSAParamsP384(ECDSAParams):
    """
    Standard FIPS-186 : P384 curve
    """
    p = int('394020061963944792122790401001436138050797392704654466679' \
            '482934042457217714968703290472660882589380018616069731123' \
            '19')
    order = int('394020061963944792122790401001436138050797392704654466' \
                '679469052796276593991132635693989563081522949135544336' \
                '53942643')
    a = (-3) % p
    b = int('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f50' \
            '13875ac656398d8a2ed19d2a85c8edd3ec2aef', 16)
    gx = int('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e08' \
             '2542a385502f25dbf55296c3a545e3872760ab7', 16)
    gy = int('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b' \
             '5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f', 16)

    def __init__(self, h=hashlib.sha256):
        curve = ECC(self.__class__.a, self.__class__.b, self.__class__.p)
        g = curve.newPoint(self.__class__.gx, self.__class__.gy)
        ECDSAParams.__init__(self, curve, g, self.__class__.order, h)

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
