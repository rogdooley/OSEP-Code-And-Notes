import argparse

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(char ^ K)

    return bytearray(out)


def main():
    parser = argparse.ArgumentParser(description="RC4 encryption/decryption")
    parser.add_argument('-k', '--key', required=True, help="The key for RC4 encryption/decryption")
    parser.add_argument('-f', '--file', required=True, help="The input file to encrypt/decrypt")
    parser.add_argument('-o', '--output', required=False, help="The encrypted/decrypted output file")
    args = parser.parse_args()

    key = [ord(c) for c in args.key]

    with open(args.file, 'rb') as file:
        data = bytearray(file.read())

    result = rc4(key, data)

    if (args.output):
        output_file = args.output
    else {
        output_file = args.file + '.out'
    }
    with open(output_file, 'wb') as file:
        file.write(result)

    print(f"Output written to {output_file}")


if __name__ == "__main__":
    main()