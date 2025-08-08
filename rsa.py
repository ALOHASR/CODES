from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Key Generation
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encryption
def encrypt_message(public_key_pem, message):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

# Decryption
def decrypt_message(private_key_pem, encrypted_message_b64):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message_b64))
    return decrypted.decode('utf-8')

# Main
if __name__ == '__main__':
    # Generate RSA key pair
    private_key, public_key = generate_keys()

    print("\n🔐 RSA Key Pair Generated!")
    print("Public Key:\n", public_key.decode())
    print("Private Key:\n", private_key.decode())

    # Get user input
    message = input("\n💬 Enter a message to encrypt: ")

    # Encrypt the user message
    encrypted_msg = encrypt_message(public_key, message)
    print("\n🔒 Encrypted Message:\n", encrypted_msg)

    # Decrypt the message
    decrypted_msg = decrypt_message(private_key, encrypted_msg)
    print("\n🔓 Decrypted Message:\n", decrypted_msg)
