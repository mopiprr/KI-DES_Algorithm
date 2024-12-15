import random
from sympy import isprime
from base64 import b64encode, b64decode


def generate_prime(bits):
    """Generate a prime number with the given number of bits."""
    while True:
        prime = random.getrandbits(bits)
        if isprime(prime):
            return prime


def gcd(a, b):
    """Calculate the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """Compute the modular multiplicative inverse of e mod phi."""
    t, new_t = 0, 1
    r, new_r = phi, e
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("e is not invertible")
    if t < 0:
        t = t + phi
    return t


class RSA:
    def __init__(self, bits=1024):
        """Initialize RSA with the specified number of bits."""
        self.p = generate_prime(bits // 2)
        self.q = generate_prime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 31  # Common choice for e
        while gcd(self.e, self.phi) != 1:
            self.e = random.randrange(2, self.phi)
        self.d = mod_inverse(self.e, self.phi)

    @staticmethod
    def encrypt(plaintext, key):
        """Encrypt a plaintext integer using the public key."""
        n, e = key
        return pow(plaintext, e, n)

    @staticmethod
    def decrypt(ciphertext, key):
        """Decrypt a ciphertext integer using the private key."""
        n, d = key
        return pow(ciphertext, d, n)

    def public_key(self):
        """Return the public key (n, e)."""
        return (self.n, self.e)

    def private_key(self):
        """Return the private key (n, d)."""
        return (self.n, self.d)

    def save_key_to_pem(self, key, filename, key_type="public"):
        """Save a key (public or private) to a .pem file."""
        n, value = key
        pem_header = f"-----BEGIN {key_type.upper()} KEY-----"
        pem_footer = f"-----END {key_type.upper()} KEY-----"
        key_data = f"{n},{value}".encode()
        encoded_key = b64encode(key_data).decode()
        with open(filename, "w") as f:
            f.write(f"{pem_header}\\n")
            f.write(f"{encoded_key}\\n")
            f.write(f"{pem_footer}\\n")

    @staticmethod
    def load_key_from_pem(filename):
        """Load a key (public or private) from a .pem file."""
        with open(filename, "r") as f:
            lines = f.readlines()
            encoded_key = "".join(lines[1:-1])  # Skip header and footer
            key_data = b64decode(encoded_key).decode()
            n, value = map(int, key_data.split(","))
            return n, value