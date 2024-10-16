import os
import argparse
import string
import random

def generate_rc4_key(length=16):
    """Generate a printable ASCII RC4 key."""
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

def generate_aes_key_iv(length=16):
    """Generate a 128-bit AES key and IV (16 bytes each)."""
    key = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))  # 128-bit AES key
    iv = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)) # 128-bit IV
    return key, iv

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RC4 or AES key and IV")
    parser.add_argument("-rc4", action="store_true", help="Generate a printable ASCII RC4 key")
    parser.add_argument("-aes", action="store_true", help="Generate a 128-bit AES key and IV")

    args = parser.parse_args()

    if args.rc4:
        rc4_key = generate_rc4_key()
        print(f"RC4 Key: {rc4_key}")

    elif args.aes:
        aes_key, aes_iv = generate_aes_key_iv()
        print(f"AES Key : {aes_key}")
        print(f"AES IV  : {aes_iv}")

    else:
        print("Please specify either -rc4 or -aes.")

