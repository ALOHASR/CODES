from hashlib import sha256
import random

def hash_message(message):
    message_hash = sha256(message.encode()).hexdigest()
    return int(message_hash, 16)

def sign_message(message, d, n):
    h = hash_message(message)
    signature = pow(h, d, n)
    return signature

def verify_signature(message, signature, e, n):
    h = hash_message(message)
    h_from_signature = pow(signature, e, n)
    return h == h_from_signature

def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=512):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(bits=512):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        return generate_keys(bits)
    d = modinv(e, phi)
    return (e, d, n)

def main():
    print("Generating RSA keys...")
    e, d, n = generate_keys(bits=512)
    print(f"\nPublic Key (e, n):\n({e}, {n})")
    print(f"Private Key (d, n):\n({d}, {n})")
    message = input("\nEnter a message to sign: ")
    signature = sign_message(message, d, n)
    print(f"\nDigital Signature:\n{signature}")
    valid = verify_signature(message, signature, e, n)
    print("\nSignature valid?", valid)

if __name__ == "__main__":
    main()
