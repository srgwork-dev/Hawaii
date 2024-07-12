import sys
import secrets
import hashlib

# Constants
A = 0
B = 7
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# Cryptographic Field Element
class FieldElement:
    """
    Represents an element in a finite field used for elliptic curve cryptography (ECC) operations.
    """

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            raise ValueError(f"Num {num} not in field range 0 to {prime - 1}")
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f"FieldElement_{self.prime}({self.num})"

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot subtract two numbers in different Fields")
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot multiply two numbers in different Fields")
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot divide two numbers in different Fields")
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


# Cryptographic Point on Curve
class Point:
    """
    Represents a point on an elliptic curve and supports various operations such as point addition and scalar multiplication.
    """

    def __init__(self, x, y, a=None, b=None):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y ** 2 != self.x ** 3 + a * x + b:
            raise ValueError(f"({x}, {y}) is not on the curve")

    def __eq__(self, other):
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        elif isinstance(self.x, FieldElement):
            return f"Point({self.x.num}, {self.y.num})_{self.a.num}_{self.b.num} FieldElement({self.x.prime})"
        else:
            return f"Point({self.x}, {self.y})_{self.a}_{self.b}"

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self}, {other} are not on the same curve")
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s ** 2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        if self == other:
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
            x = s ** 2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


# Field Element for SHA-256
class Sha256Field(FieldElement):
    """
    Represents a field element using SHA-256 as the underlying prime field.
    """

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return f"{self.num:x}".zfill(64)

    def sqrt(self):
        return self ** ((P + 1) // 4)


# Point on Curve using SHA-256
class Sha256Point(Point):
    """
    Represents a point on the elliptic curve using SHA-256 for cryptographic operations.
    """

    def __init__(self, x, y, a=None, b=None):
        a, b = Sha256Field(A), Sha256Field(B)
        if type(x) == int:
            super().__init__(x=Sha256Field(x), y=Sha256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return "Sha256Point(infinity)"
        else:
            return f"Sha256Point({self.x}, {self.y})"

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def sec(self, compressed=True):
        if compressed:
            if self.y.num % 2 == 0:
                return b"\x02" + self.x.num.to_bytes(32, "big")
            else:
                return b"\x03" + self.x.num.to_bytes(32, "big")
        else:
            return b"\x04" + self.x.num.to_bytes(32, "big") + self.y.num.to_bytes(32, "big")

    def encode_base58(self, s):
        count = 0
        for c in s:
            if c == 0:
                count += 1
            else:
                break
        num = int.from_bytes(s, "big")
        prefix = "1" * count
        result = ""
        while num > 0:
            num, mod = divmod(num, 58)
            result = BASE58_ALPHABET[mod] + result
        return prefix + result

    def encode_base58_checksum(self, b):
        return self.encode_base58(b + (hashlib.sha256(hashlib.sha256(b).digest()).digest())[:4])

    def address(self, compressed=True, testnet=False):
        h160 = self._hash160(self.sec(compressed))
        prefix = b"\x6f" if testnet else b"\x00"
        return self.encode_base58_checksum(prefix + h160)

    def _hash160(self, s):
        return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()

    @classmethod
    def parse(cls, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], "big")
            y = int.from_bytes(sec_bin[33:65], "big")
            return Sha256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = Sha256Field(int.from_bytes(sec_bin[1:], "big"))
        alpha = x ** 3 + Sha256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = Sha256Field(P - beta.num)
        else:
            even_beta = Sha256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return Sha256Point(x, even_beta)
        else:
            return Sha256Point(x, odd_beta)


# Signature for ECDSA
class Signature:
    """
    Represents a digital signature used in elliptic curve cryptography (ECC) and the Elliptic Curve Digital Signature Algorithm (ECDSA).
    """

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return f"Signature({self.r}, {self.s})"


# Private Key for ECDSA
class PrivateKey:
    """
    Represents a private key in elliptic curve cryptography (ECC) and provides methods for signing messages and generating public keys.
    """

    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return f"{self.secret:x}".zfill(64)

    def sign(self, z):
        k = secrets.randbelow(N)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, "big")
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        return self.point.encode_base58_checksum(prefix + secret_bytes + suffix)


# Elliptic Curve Generator Point
G = Sha256Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# Double SHA-256 Hash Function
def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


# Main Execution for Example Usage
if __name__ == "__main__":
    secret = 0x12345abcdef67890
    private_key = PrivateKey(secret)
    print("Private Key:", private_key.hex())

    z = 0xabcdef1234567890
    signature = private_key.sign(z)
    print("Signature (r, s):", signature.r, signature.s)

    public_key = private_key.point
    print("Public Key:", public_key)

    message = b"Hello, world!"
    digest = hashlib.sha256(message).digest()
    address = public_key.address()
    print("Address:", address)
