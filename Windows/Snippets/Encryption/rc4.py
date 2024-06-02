from arc4 import ARC4

# pip install arc4

def encrypt(data, key):
    cipher = ARC4(key)
    return cipher.encrypt(data)

def decrypt(data, key):
    cipher = ARC4(key)
    return cipher.decrypt(data)

# Example usage
key = b'your-key'
data = b'your-data'

encrypted = encrypt(data, key)
print("Encrypted:", encrypted)

decrypted = decrypt(encrypted, key)
print("Decrypted:", decrypted.decode())