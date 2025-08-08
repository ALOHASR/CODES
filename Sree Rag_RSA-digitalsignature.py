from hashlib import sha256

# Convert message to hash using SHA-256
def hash_message(message):
    message_hash = sha256(message.encode()).hexdigest()
    return int(message_hash, 16)

# Verify RSA signature
def verify_signature(message, signature, e, n):
    h = hash_message(message)
    h_from_signature = pow(signature, e, n)
    return h == h_from_signature
