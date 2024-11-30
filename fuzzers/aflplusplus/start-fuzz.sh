#!/bin/bash
set -ex

# Set environment variables if not set
FUZZER_INPUTS=${FUZZER_INPUTS:-/corpus/inputs}
FUZZER_CORPUS=${FUZZER_CORPUS:-/corpus/corpus}
SEED=${SEED:-1}

mkdir -p $FUZZER_INPUTS $FUZZER_CORPUS

# Add an empty seed file if it doesn't exist
if [ ! -f $FUZZER_INPUTS/seed ]; then
    echo 1 > $FUZZER_INPUTS/seed
fi


/usr/local/bin/afl-fuzz \
    -i $FUZZER_INPUTS \
    -o $FUZZER_CORPUS \
    -s $SEED \
    -t 1000+ \
    -- \
    $OUT/$FUZZ_TARGET
