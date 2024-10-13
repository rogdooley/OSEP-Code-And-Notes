import argparse
import random
import string

# RC4 Key Scheduling Algorithm (KSA)
def rc4_ksa(key):
    key_length = len(key)
    S = list(range(256))
    
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
    
    return S

# RC4 Pseudo-Random Generation Algorithm (PRGA)
def rc4_prga(S, data_length):
    i = 0
    j = 0
    key_stream = []
    
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
        key_stream.append(S[(S[i] + S[j]) % 256])
    
    return key_stream

# RC4 encryption/decryption (they are the same operation)
def rc4_encrypt_decrypt(data, key):
    key = [ord(c) for c in key]  # Convert key to ASCII values
    S = rc4_ksa(key)            # Key scheduling algorithm
    key_stream = rc4_prga(S, len(data))  # Generate key stream
    
    # XOR the data with the key stream
    return bytearray([data[i] ^ key_stream[i] for i in range(len(data))])

# Function to read hex array from file
def read_hex_array_from_file(file_path):
    with open(file_path, 'r') as file:
        hex_data = file.read()
    
    hex_data = hex_data.replace('\n', '').replace(' ', '').replace('0x', '').replace(',', '')
    byte_array = bytearray.fromhex(hex_data)
    return byte_array

# Generate a random ASCII key
def generate_random_key(key_length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation.replace('"', '').replace("'", '').replace('\\', '').replace('`', '')) for _ in range(key_length))

# Function to format the output like C# byte array
def format_output(byte_array):
    hex_string = []
    counter = 0
    for b in byte_array:
        hex_string.append(f"{b}, ")
        counter += 1
        if counter % 50 == 0:
            hex_string.append(f"_\n")
    return ''.join(hex_string).strip()

# Main function
def main():
    parser = argparse.ArgumentParser(description="Encrypt a hex array from a file using RC4 and output the result.")
    parser.add_argument("-f", "--file", required=True, help="Input file containing hex array (from msfvenom).")
    parser.add_argument("-k", "--key", required=False, help="Encryption key (randomly generated if not provided).")
    parser.add_argument("-o", "--output", required=True, help="Output file to save the encrypted payload.")

    args = parser.parse_args()

    # Read the hex array from the file
    buffer = read_hex_array_from_file(args.file)

    # Generate key if not provided
    key = args.key if args.key else generate_random_key()
    print(f"Encryption key: {key}")

    # Encrypt the buffer using RC4
    encrypted = rc4_encrypt_decrypt(buffer, key)

    # Format output
    formatted_output = format_output(encrypted)

    # Write the encrypted payload to the output file
    with open(args.output, 'w') as output_file:
        output_file.write(f"byte[] buf = new byte[{len(encrypted)}] {{\n{formatted_output}\n}};")

    print(f"Encrypted payload saved to {args.output}")

if __name__ == "__main__":
    main()
