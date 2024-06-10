import argparse

def rc4(key, data):
    S = list(range(256))
    j = 0

    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    out = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

def main():
    parser = argparse.ArgumentParser(description='RC4 Encoder/Decoder')
    parser.add_argument('-k', '--key', required=True, help='Encryption/Decryption key')
    parser.add_argument('-s', '--string',  help='String to encode/decode')
    parser.add_argument('-b', '--bytearray', help='Byte array to decode')
    parser.add_argument('-o', '--operation', required=True, choices=['encode', 'decode'], help='Operation: encode or decode')
    parser.add_argument('-a', '--alternative', choices=['vb'], help='Alternative encoding ouput')

    args = parser.parse_args()

    key = args.key.encode('utf-8')

    if args.operation == 'encode':
        if not args.string:
            print("Error: For encoding, please provide a string using the -s option.")
            return

        data = args.string.encode('utf-8')
        result = rc4(key, data)

        if not args.alternative:
            byte_array_result = ', '.join(f'0x{byte:02x}' for byte in result)
            print(f"Byte array result: [{byte_array_result}]")
        elif args.alternative == 'vb':
            byte_array_result = ', '.join(f'H&{byte:02x}' for byte in result)
            print(f"Byte array result: [{byte_array_result}]")
        

    elif args.operation == 'decode':
        if not args.bytearray:
            print("Error: For decoding, please provide a byte array using the -b option.")
            return

        data = bytearray(ast.literal_eval(args.bytearray))
        result = rc4(key, data)
        print(f"Decoded string: {result.decode('utf-8')}")


if __name__ == '__main__':
    main()

