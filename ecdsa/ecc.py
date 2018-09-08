from .utils import invMod

class ECCPoint:
    """
    Represent a point on an elliptic curve over a finite field.
    Attributes:
         curve : the ECC object representing the curve
         x : the x-coordinate of the point
         y : the y-coordinate of the point
    """
    def __init__(self, curve, x, y):
        if not isinstance(curve, ECC):
            raise Exception("First parameter must be type ECC")

        self.curve = curve
        self.x = x % self.curve.p
        self.y = y % self.curve.p

        if not self.isOnCurve():
            raise Exception("Point %s is not on the curve !" % self)

    def isOnCurve(self):
        """ Check if the point is on the curve """
        if self.isInfinity():
            return True
        v1 = pow(self.y, 2, self.curve.p)
        v2 = pow(self.x, 3, self.curve.p) + self.x * self.curve.a + self.curve.b
        v2 %= self.curve.p
        return v1 == v2

    def isInfinity(self):
        """ Check if it's the special point at infinity """
        return False

    def copy(self):
        """ Create a copy of the current point """
        if self.isInfinity():
            return ECCInfinitePoint(self.curve)
        return ECCPoint(self.curve, self.x, self.y)

    def __add__(self, other):
        """ Point addition : P1 + P2 """
        if self.curve != other.curve:
            raise Exception("You can only add point living in the same group !")

        # Special cases
        if self.isInfinity():
            return other.copy()
        if other.isInfinity():
            return self.copy()
        if self == -other:
            return ECCInfinitePoint(self.curve)

        curve = self.curve
        (a, b, p) = (curve.a, curve.b, curve.p)
        (x1, y1) = (self.x, self.y)
        (x2, y2) = (other.x, other.y)

        # General case
        if self == other:
            l = ((3*pow(x1, 2, p) + a) * invMod(2*y1, p)) % p
        else:
            l = ((y2 - y1) * invMod(x2 - x1, p)) % p

        x = (l**2 - x1 - x2) % p
        y = (l * (x1 - x) - y1) % p

        return ECCPoint(curve, x, y)

    def __mul__(self, k):
        """
        Multiplication of a point : [k]P
        The Montgomery ladder is used to prevent timing attacks.
        """
        r0 = ECCInfinitePoint(self.curve)
        r1 = self.copy()

        for i in range(self.curve.p.bit_length(), -1, -1):
            if (k & (1 << i)) == 0:
                r1 += r0
                r0 += r0
            else:
                r0 += r1
                r1 += r1
        return r0

    def __rmul__(self, k):
        """ Multiplication is commutative : kP = Pk """
        return self * k

    def __eq__(self, other):
        """ Test equality of two points """
        if self.curve != other.curve:
            return False
        if self.isInfinity():
            return other.isInfinity()
        if other.isInfinity():
            return False
        return (self.x, self.y) == (other.x, other.y)

    def __ne__(self, other):
        """ Test inequality of two points """
        return not self.__eq__(other)

    def __neg__(self):
        """ Inverse of a point : -(x, y) = (x, -y) """
        if self.isInfinity():
            return ECCInfinitePoint(self.curve)
        return ECCPoint(self.curve, self.x, (-self.y) % self.curve.p)

    def __repr__(self):
        """ String representation of a point """
        if self.isInfinity():
            return "Infinite on %s" % (self.curve)
        else:
            return "(%d,%d) on %s" % (self.x, self.y, self.curve)

class ECCInfinitePoint(ECCPoint):
    """
    Special point at infinite (neutral element of addition law)
    """
    def __init__(self, curve):
        self.curve = curve

    def isInfinity(self):
        """ It's Infinite point """
        return True

class ECC:
    """
    Representation of an elliptic curve over finite field.
    E(Fp) = Y^2 = X^3 + AX + B (mod p)
    Attributes:
         a: constant A of the elliptic curve
         b: constant B of the elliptic curve
         p: modulus defining the finite field Fp

    """
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

        if self.isSingular():
            raise Exception("Curve %s is singular !" % self)


    def newPoint(self, x, y):
        """ Create a new EC point (x, y) """
        return ECCPoint(self, x, y)

    def newInfinitePoint(self):
        """ Create a new infinite point """
        return ECCInfinitePoint(self)

    def determinant(self):
        """ Determinant of the curve """
        return (-16 * (4*self.a**3 + 27*self.b**2)) % self.p

    def isSingular(self):
        """ Check if the curve is singular """
        return self.determinant() == 0

    def __repr__(self):
        """ String representation of the curve """
        return "Y^2 = X^3 + %dX + %d [mod %d]" % (self.a, self.b, self.p)

    def __eq__(self, other):
        """ Test if two curves are equals """
        return (self.a, self.b, self.p) == (other.a, other.b, other.p)

    def __ne__(self, other):
        """ Test if two curves are differentes """
        return not self.__eq__(other)
