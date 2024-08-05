#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

BINARY=$1

echo "Functions called:"
# Run ltrace and capture function calls
ltrace -c $BINARY 2>&1 | awk '/^ / {print $4" "$5}' | sort | tee ltrace_output.txt

echo " "
echo "Functions called only once:"
# Display potential hijackable functions (called only once)
awk '$1 == 1 {print $2}' ltrace_output.txt
