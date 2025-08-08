from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# --- AES Encryption ---
def aes_encrypt(plaintext: bytes, key: bytes) -> (bytes, bytes):
    iv = get_random_bytes(16)  # AES block size = 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext

# --- AES Decryption ---
def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# --- Example Usage ---
if __name__ == "__main__":
    key = get_random_bytes(32)  # AES-256 (32 bytes key)
    message = b"This is a secret file data."

    # Encrypt
    iv, ciphertext = aes_encrypt(message, key)
    print("Ciphertext (Base64):", base64.b64encode(iv + ciphertext).decode())

    # Simulate download of key
    print("Encryption Key (Base64):", base64.b64encode(key).decode())

    # Decrypt
    decrypted = aes_decrypt(iv, ciphertext, key)
    print("Decrypted:", decrypted.decode())
