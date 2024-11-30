#!/bin/bash

set -ex

DOCKER_CODESYS_BASE="codesys"
DOCKER_IMAGE="codesys-sample"
SAMPLE_PROGRAM="benchmarks/oscat_basic_charname"

# Require running from the git root
if [ ! -d ".git" ]; then
    echo "This script must be run from the project root"
    exit 1
fi

# Ensure ASLR is disabled
if [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]; then
    echo "ASLR must be disabled to run this script"
    exit 1
fi

# Build the CODESYS Docker Image
docker build -t $DOCKER_CODESYS_BASE \
    compiler/codesys/
docker build -t $DOCKER_IMAGE \
    -f compiler/codesys/sample.Dockerfile \
    --build-context codesys-base=docker-image://$DOCKER_CODESYS_BASE \
    --build-context program=$SAMPLE_PROGRAM \
    compiler/codesys/

# Run the CODESYS Docker Image to locate area zero script
CONTAINER_ID=$(docker run -d --rm --cap-add SYS_PTRACE --privileged $DOCKER_IMAGE)

# Wait for program to start
echo "Waiting for CODESYS to start..."
sleep 5

# Run area zero script
docker exec -it $CONTAINER_ID /bin/bash /locate-area-zero.sh

# Copy result
mkdir -p .config
docker cp $CONTAINER_ID:/codesys-area-zero .config/

# Stop the container
docker rm --force $CONTAINER_ID

# Delete the cache such that the next run will rebuild the image
rm -rf .cache