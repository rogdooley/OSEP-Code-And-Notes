import argparse

class RC4:
    def __init__(self, key):
        self.S = list(range(256))
        self.key = [ord(c) for c in key]
        self.x = 0
        self.y = 0
        self._ksa()

    def _ksa(self):
        j = 0
        key_length = len(self.key)
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def _prga(self):
        while True:
            self.x = (self.x + 1) % 256
            self.y = (self.y + self.S[self.x]) % 256
            self.S[self.x], self.S[self.y] = self.S[self.y], self.S[self.x]
            K = self.S[(self.S[self.x] + self.S[self.y]) % 256]
            yield K

    def crypt(self, data):
        data = [ord(c) for c in data]
        keystream = self._prga()
        return ''.join(chr(c ^ next(keystream)) for c in data)


def main():
    parser = argparse.ArgumentParser(description="RC4 encryption/decryption")
    parser.add_argument('-k', '--key', required=True, help="The key for RC4 encryption/decryption")
    parser.add_argument('-f', '--file', required=True, help="The input file to encrypt/decrypt")
    parser.add_argument('-o', '--output', required=True, help="The encrypted output file")

    args = parser.parse_args()

    with open(args.file, 'r') as file:
        data = file.read()

    rc4 = RC4(args.key)
    encrypted_data = rc4.crypt(data)

    with open(args.output + '.enc', 'w') as file:
        file.write(encrypted_data)

    print(f"File encrypted and saved as {args.output}.enc")


if __name__ == "__main__":
    main()