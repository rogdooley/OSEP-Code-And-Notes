#!/bin/bash

# Check if a library path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <library-path>"
    exit 1
fi

LIBRARY="$1"

# Directories to search for binaries
DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

# Find all binaries and check if they are linked to the provided library
for dir in $DIRS; do
    for binary in $(find "$dir" -type f -executable); do
        if ldd "$binary" 2>/dev/null | grep -q "$LIBRARY"; then
            echo "Binary '$binary' is linked to '$LIBRARY'"
        fi
    done
done
