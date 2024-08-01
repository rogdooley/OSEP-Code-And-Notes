#!/bin/bash

if [ "$#" -ne 2 ]; then
            echo "Usage: $0 <shared_library.so> <path_to_search>"
                exit 1
        fi

        LIBRARY=$1
        SEARCH_PATH=$2

        echo "Searching for binaries that use $LIBRARY in $SEARCH_PATH..."

        find $SEARCH_PATH -type f -executable -print0 | while IFS= read -r -d '' file; do
            if ldd "$file" 2>/dev/null | grep -q "$LIBRARY"; then
                            echo "Found: $file"
                                fi
                        done
