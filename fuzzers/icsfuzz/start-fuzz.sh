#!/bin/bash

set -exu

# Ensure ASLR is disabled by reading /proc/sys/kernel/randomize_va_space
ASLR_STATUS=$(cat /proc/sys/kernel/randomize_va_space)
if [[ "$ASLR_STATUS" -eq 1 || "$ASLR_STATUS" -eq 2 ]]; then
    echo "Error: ASLR is enabled (value: $ASLR_STATUS)."
    exit 1
else
    echo "ASLR is disabled."
fi

# Read a harness.env file if it exists
if [ -f harness.env ]; then
    source harness.env
fi

# Use $TARGET_OFFSET to calculate the target address (add to $CODESYS_AREA_ZERO)
# Result in hex
TARGET_ADDR=$(printf "0x%X\n" $((CODESYS_AREA_ZERO + TARGET_OFFSET)))

# Start CODESYS
/bin/bash /start.sh &
CODESYS_PID=$!

# Kill CODESYS process on exit
cleanup() {
    echo "Shutting down CODESYS..."
    kill $CODESYS_PID 2>/dev/null
}

# Trap the EXIT signal to call the cleanup function when the script exits
trap cleanup EXIT

# Startup script to wait for CODESYS to start for the first time
echo "Waiting for CODESYS...."
sleep 5

FUZZER_PID=""
start_fuzzer() {
    # Try to fetch the Codesys and main task TID
    # I.e.: ` 104 128 ? 00:00:00 MainTask
    TASK=$(ps -AT | grep $PLCTASK | tr -s ' ')
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

    # Start fuzzer
    echo "Starting fuzzer"
    ./fuzzer $CODESYS_PID $TARGET_ADDR $TARGET_SIZE $MAINTASK_TID &
    FUZZER_PID=$!
}

while true; do

    # Start fuzzing process
    start_fuzzer

    # Watch for crashes
    inotifywait -m -e modify "$CODESYS_LOG" |
    while read path action file; do
        # Execute when crash starts
        echo "Detected a CODESYS Crash!"

        # Stop previous fuzzer
        kill $FUZZER_PID

        # Allow a few seconds for CODESYS to come online
        sleep 5

        # Restart Fuzzer
        start_fuzzer
    done
done
