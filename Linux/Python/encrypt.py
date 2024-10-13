import argparse
import os
import random
import string
import secrets
import binascii
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from Cryptodome.Hash import SHA256

# Function to generate a key and optionally an IV/nonce
def generate_key(key_length, iv_length=0):
    safe_characters = string.ascii_letters + string.digits + string.punctuation.replace('"', '').replace("'", '').replace('\\', '').replace('`', '')

    # Generate the key
    key = ''.join(random.choice(safe_characters) for _ in range(key_length))

    # Generate the IV or nonce if required (iv_length > 0)
    iv_or_nonce = ''.join(random.choice(safe_characters) for _ in range(iv_length)) if iv_length > 0 else None

    key_bytes = secrets.token_bytes(key_lenght)
    key_hex = binascii.hexlify(key_bytes).decode('ascii')
    iv_or_nonce = binascii.hexlify(secrets.token_bytes(iv_length)).decode('ascii')

    return key, iv_or_nonce


def generate_hex_key(key_length, iv_length=0):
    # Generate a random key as a hex string
    key = os.urandom(key_length).hex()

    # Generate the IV or nonce if required (iv_length > 0)
    iv_or_nonce = os.urandom(iv_length).hex() if iv_length > 0 else None

    return key, iv_or_nonce


def encrypt_aes(shellcode, key, iv):
    key_bytes = bytes.fromhex(key)  # Convert hex string to bytes
    iv_bytes = bytes.fromhex(iv)  # Convert hex string to bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    encrypted = cipher.encrypt(pad(shellcode, AES.block_size))
    return encrypted


# Function to encrypt using RC4
def encrypt_rc4(shellcode, key):
    cipher = ARC4.new(key.encode('utf-8'))
    return cipher.encrypt(shellcode)


# Function to encrypt using ChaCha20
def encrypt_chacha20(shellcode, key, nonce):
    cipher = ChaCha20.new(key=key.encode('utf-8'), nonce=nonce)
    encrypted = cipher.encrypt(shellcode)
    return nonce + encrypted  # Prepend nonce to encrypted data


def main():
    parser = argparse.ArgumentParser(description='Encrypt shellcode using AES, RC4, or ChaCha20.')
    parser.add_argument('-k', '--key-file', required=True, help='File to save generated keys')
    parser.add_argument('-o', '--output', required=True, help='Output file for encrypted shellcode')
    parser.add_argument('-i', '--input', required=True, help='Input shellcode file')
    parser.add_argument('--aes', action='store_true', help='Use AES for encryption')
    parser.add_argument('--rc4', action='store_true', help='Use RC4 for encryption')
    parser.add_argument('--chacha20', action='store_true', help='Use ChaCha20 for encryption')

    args = parser.parse_args()

    # Read shellcode from input file
    with open(args.input, 'rb') as f:
        shellcode = f.read()

    # Generate the key and, if needed, the IV/nonce
    if args.rc4:
        key, iv_or_nonce = generate_random_key(16)
    elif args.aes:
        key, iv_or_nonce = generate_hex_key(32, 16)  # AES key is 32 bytes, IV is 16 bytes
    elif args.chacha20:
        key, iv_or_nonce = generate_key(32, 12)  # ChaCha20 key is 32 bytes, nonce is 12 bytes


    # Encrypt shellcode based on specified method
    encrypted = None
    if args.aes:
        encrypted = encrypt_aes(shellcode, key, iv_or_nonce)
    elif args.rc4:
        encrypted = encrypt_rc4(shellcode, key)
    elif args.chacha20:
        encrypted = encrypt_chacha20(shellcode, key, iv_or_nonce)

    # Write the key (and IV/nonce if applicable) to the key file
    with open(args.key_file, 'w') as key_file:
        key_file.write(f"{key}\n")
        if iv_or_nonce:
            key_file.write(f"{iv_or_nonce}\n")

    if encrypted:
        with open(args.output, 'wb') as f:
            f.write(encrypted)

        # Output encrypted data as a hex string for C# compatibility
        hex_data = ', '.join(f'0x{byte:02x}' for byte in encrypted)
        print(f"Encrypted shellcode (Hex): {{ {hex_data} }};")

if __name__ == "__main__":
    main()
