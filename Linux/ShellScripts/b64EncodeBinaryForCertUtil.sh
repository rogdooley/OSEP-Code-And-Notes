#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <binary_file> <output_file>"
    exit 1
fi

# Input binary file
binary_file="$1"

# Output file
output_file="$2"

# Check if the input file exists
if [ ! -f "$binary_file" ]; then
    echo "Error: Input file $binary_file does not exist."
    exit 1
fi

# Base64 encode the binary file
openssl base64 -in "$binary_file" -out temp.b64

# Add certificate headers and footers
{
  echo "-----BEGIN CERTIFICATE-----"
  cat temp.b64
  echo "-----END CERTIFICATE-----"
} > "$output_file"

# Clean up temporary file
rm temp.b64

echo "Encoded file saved as $output_file"

