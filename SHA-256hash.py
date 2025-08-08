import hashlib

def compute_sha256(text):
    hash_object = hashlib.sha256(text.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

def main():
    message = input("Enter a message to hash (SHA-256): ")
    hash_result = compute_sha256(message)
    print("\nSHA-256 Hash:")
    print(hash_result)

if __name__ == "__main__":
    main()
