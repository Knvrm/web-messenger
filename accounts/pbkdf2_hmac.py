import os

class SHA256:
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _right_rotate(self, x, n):
        return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

    def _pad_message(self, message):
        ml = len(message) * 8
        message += b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        message += ml.to_bytes(8, 'big')
        return message

    def hash(self, message):
        message = self._pad_message(message)
        for i in range(0, len(message), 64):
            w = [0] * 64
            for j in range(16):
                w[j] = int.from_bytes(message[i + j*4:i + j*4 + 4], 'big')
            for j in range(16, 64):
                s0 = self._right_rotate(w[j-15], 7) ^ self._right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
                s1 = self._right_rotate(w[j-2], 17) ^ self._right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
                w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = self.h
            for j in range(64):
                s1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
                ch = (e & f) ^ (~e & g)
                temp1 = (h + s1 + ch + self.k[j] + w[j]) & 0xFFFFFFFF
                s0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF

            self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
            self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
            self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
            self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
            self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

        return ''.join(f'{h:08x}' for h in self.h)

class HMAC:
    def __init__(self, key, message, hash_func=SHA256):
        self.hash_func = hash_func
        self.block_size = 64
        if len(key) > self.block_size:
            key = self.hash_func().hash(key).encode('utf-8')
        if len(key) < self.block_size:
            key += b'\x00' * (self.block_size - len(key))
        self.key = key
        self.ipad = b'\x36' * self.block_size
        self.opad = b'\x5c' * self.block_size
        self.message = message

    def digest(self):
        inner_hash = self.hash_func().hash(bytes(a ^ b for a, b in zip(self.key, self.ipad)) + self.message)
        outer_hash = self.hash_func().hash(bytes(a ^ b for a, b in zip(self.key, self.opad)) + inner_hash.encode('utf-8'))
        return outer_hash

class PBKDF2:
    def __init__(self, password, salt, iterations=1000, key_length=32):
        self.password = password.encode('utf-8')
        self.salt = salt
        self.iterations = iterations
        self.key_length = key_length
        self.hash_func = SHA256

    def derive_key(self):
        result = ''
        block_count = (self.key_length + 31) // 32
        for i in range(1, block_count + 1):
            u = HMAC(self.password, self.salt + i.to_bytes(4, 'big'), self.hash_func).digest()
            t = u
            for _ in range(1, self.iterations):
                u = HMAC(self.password, u.encode('utf-8'), self.hash_func).digest()
                t = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(t, u))
            result += t
        return result[:self.key_length].encode('latin1').hex()

def generate_salt(length=16):
    return os.urandom(length)

def hash_password(password):
    salt = generate_salt()
    pbkdf2 = PBKDF2(password, salt)
    hashed = pbkdf2.derive_key()
    return salt, hashed

def verify_password(stored_salt, stored_hash, password):
    pbkdf2 = PBKDF2(password, stored_salt)
    hashed = pbkdf2.derive_key()
    return hashed == stored_hash