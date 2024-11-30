#!/bin/bash

set -ex

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

echo "Starting fuzzer!"
python2 fuzz_iec.py ./profiles/harness.json
