#!/bin/bash

# Locate Main PLC Task PID
PLC_TASK="MainTask"
TASK=$(ps -AT | grep $PLC_TASK | tr -s ' ')
CODESYS_PID=$(echo "$TASK" | cut -d' ' -f2)
MAINTASK_TID=$(echo "$TASK" | cut -d' ' -f3)
echo "Identified: CODESYS=$CODESYS_PID, MAINTASK=$MAINTASK_TID"

if [ -z "$CODESYS_PID" ]; then
    echo "Unable to find CODESYS proc!"
    exit 1
fi

if [ -z "$MAINTASK_TID" ]; then
    echo "Unable to find PLC Task ($PLCTASK) proc!"
    exit 1
fi

PID=$MAINTASK_TID

# Use these unique strings to identify the right memory region for Area0
TARGET_STRINGS=(
    "Application"
    "IEC-Tasks"
    "MainTask"
    # "__MAIN"
    # "PLC_PRG"
    # "IoConfig_Globals"
    # "iostandard, 3.5.16.0 (system)"
)

# Create a temporary file for storing memory content
TEMP_FILE=$(mktemp)

# Function to clean up the temporary file on exit
cleanup() {
    rm -f "$TEMP_FILE"
}
trap cleanup EXIT

# Iterate over each memory region in /proc/<pid>/maps
while IFS= read -r line; do
    # Extract the memory range and permissions
    RANGE=$(echo "$line" | awk '{print $1}')
    PERMS=$(echo "$line" | awk '{print $2}')

    # Only read regions with "rw-p" permissions
    if [[ "$PERMS" == "rw-p" ]]; then
        START=$(echo "$RANGE" | cut -d'-' -f1)
        END=$(echo "$RANGE" | cut -d'-' -f2)
        echo "Reading $START-$END with permissions $PERMS"

        # Calculate the size to read
        SIZE=$((0x$END - 0x$START))
        echo "Size: $SIZE"

        # Only read size 1MB
        if [[ "$SIZE" -ne 1048576 ]]; then
            continue
        fi

        # Dump the memory region to the temporary file, removing null bytes
        dd if=/proc/$PID/mem bs=1 skip=$((0x$START)) count=$SIZE 2>/dev/null | tr -d '\000' > "$TEMP_FILE"

        # Initialize the starting offset for search
        OFFSET=0
        ALL_FOUND=true

        # Search for each string in sequence within the temporary file
        for TARGET_STRING in "${TARGET_STRINGS[@]}"; do
            # Find the target string starting from the current offset in the temporary file
            STRING_OFFSET=$(grep -abo "$TARGET_STRING" "$TEMP_FILE" | awk -F':' -v min_offset="$OFFSET" '$1 >= min_offset {print $1; exit}')

            if [[ -z "$STRING_OFFSET" ]]; then
                # If any string is missing, set flag and exit the loop
                ALL_FOUND=false
                break
            else
                # Update OFFSET to search sequentially after the found string
                OFFSET=$((STRING_OFFSET + ${#TARGET_STRING}))
                # Calculate the absolute address
                ADDRESS=$(printf "0x%X\n" $((0x$START + STRING_OFFSET)))
                echo "Found $TARGET_STRING at address: $ADDRESS"
            fi
        done

        # If all strings were found in sequence, exit early
        if [[ "$ALL_FOUND" == true ]]; then
            echo "All strings found in sequence."
            echo "Start Memory Region:"
            echo $START
            echo "0x$START" >> /codesys-area-zero
            exit 0
        fi
    fi
done < /proc/$PID/maps

echo "All strings not found in sequence in any memory region."
exit 1

find . -path '*/fieldfuzz/harness.json' | while read -r filepath; do
    folder=$(dirname "$filepath" | cut -d'/' -f2)

    # Remove the specific line from the harness.env file if it exists
    sed -i '/^TARGET_ADDR=/d' "$folder/icsfuzz/harness.env"

done
