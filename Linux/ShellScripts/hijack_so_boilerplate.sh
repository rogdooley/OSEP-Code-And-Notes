#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input_shared_library.so> <output_shared_library.so>"
    exit 1
fi

INPUT_LIB=$1
OUTPUT_LIB=$2
HEADER="mylib.h"
VERSION_SCRIPT_BASE="mylib"
TMP_FILE="symbols.txt"
SOURCE="mylib.c"

# Extract function symbols from the shared library
readelf -s --wide $INPUT_LIB | grep FUNC | grep -v '@GLIB' > $TMP_FILE

# Generate header file
echo "Generating header file..."
echo "#ifndef MYLIB_H" > $HEADER
echo "#define MYLIB_H" >> $HEADER

# Initialize source file
echo "#include <stdio.h>" > $SOURCE
echo "#include \"$HEADER\"" >> $SOURCE
echo "int main() {" >> $SOURCE

# Process each line from the readelf output
while IFS= read -r line; do
    # Extract the symbol name and potential version information
    symbol=$(echo $line | awk '{print $8}')
    version=$(echo $symbol | grep -o '@.*')

    # Check if the symbol has version information
    if [[ -n $version ]]; then
        # Strip the '@' and use the version information to determine the map file
        base_symbol=$(echo $symbol | sed 's/@.*//')
        version_name=$(echo $version | sed 's/@//' | sed 's/@//')
        map_file="${VERSION_SCRIPT_BASE}_${version_name}.map"

        # Append the symbol to the appropriate map file
        echo "Adding $base_symbol to $map_file..."
        if [ ! -f $map_file ]; then
            echo "MYLIB_${version_name} {" > $map_file
            echo "    global:" >> $map_file
            echo "        $base_symbol;" >> $map_file
            echo "    local:" >> $map_file
            echo "        *;" >> $map_file
            echo "};" >> $map_file
        else
            sed -i "/global:/a\        $base_symbol;" $map_file
        fi
    else
        # Append the symbol to the header file
        echo "void $symbol();" >> $HEADER
        echo "    $symbol();" >> $SOURCE
    fi
done < $TMP_FILE

# Finalize the header file
echo "#endif // MYLIB_H" >> $HEADER

# Finalize the source file
echo "    return 0;" >> $SOURCE
echo "}" >> $SOURCE

# Clean up
rm $TMP_FILE

echo "Header file generated: $HEADER"
echo "Version scripts generated: $(ls ${VERSION_SCRIPT_BASE}_*.map)"

# Compile the shared library
echo "Compiling the shared library..."
gcc -fPIC -c $SOURCE -o mylib.o

# Create the shared library
map_files=$(ls ${VERSION_SCRIPT_BASE}_*.map 2>/dev/null)
if [[ -n $map_files ]]; then
    echo "Linking with version scripts: $map_files"
    gcc -shared -Wl,$(for map in $map_files; do echo -n "--version-script=$map,"; done | sed 's/,$//') -o $OUTPUT_LIB mylib.o
else
    gcc -shared -o $OUTPUT_LIB mylib.o
fi

# Clean up object file
rm mylib.o

echo "Shared library created: $OUTPUT_LIB"