import subprocess
import os
import json

from loguru import logger as log
from src.config import BENCHMARKS_DIR, COMPILER_DIR, FUZZERS_DIR

CACHE_DIR = ".cache"
DOCKER_FUZZER_IMAGE_CACHE_FILE = os.path.join(CACHE_DIR, "docker_fuzzer_images.json")
DOCKER_BENCHMARK_IMAGE_CACHE_FILE = os.path.join(
    CACHE_DIR, "docker_benchmark_images.json"
)
DOCKER_COMPILER_IMAGE_CACHE_FILE = os.path.join(
    CACHE_DIR, "docker_compiler_images.json"
)

# TODO - add CODESYS cache
# TODO - per fuzzer cache
# TODO - per benchmark cache
# ALL_FUZZER_CONTEXTS = list(set([fuzzer.fuzzer_context for fuzzer in all_fuzzers]))

CACHE_CHECKS = {
    "BENCHMARKS": {
        "directory": BENCHMARKS_DIR,
        "docker_cache": {},
        "cache_file": DOCKER_BENCHMARK_IMAGE_CACHE_FILE,
    },
    "COMPILERS": {
        "directory": COMPILER_DIR,
        "docker_cache": {},
        "cache_file": DOCKER_COMPILER_IMAGE_CACHE_FILE,
    },
    "FUZZERS": {
        "directory": FUZZERS_DIR,
        "docker_cache": {},
        "cache_file": DOCKER_FUZZER_IMAGE_CACHE_FILE,
    },
}


def get_dir_hash(dir: str):
    """
    Returns the MD5 hash of all files in a directory
    """
    # Print cwd
    command = (
        "find "
        + os.path.join(os.getcwd(), dir)
        + ' -type f -exec md5sum {} + | sort | md5sum | cut -d" " -f1'
    )
    return subprocess.check_output([command], shell=True, text=True)


def validate_dirs_cache(dirs: str | list):
    """
    Check if a list of directories have changed since the last run
    """
    cache_valid = True

    if not isinstance(dirs, list):
        dirs = [dirs]

    for dir in dirs:
        dir_hash = get_dir_hash(dir).strip()
        dir_clean = dir.replace("/", "_")  # Clean the path for the cache file

        # Create the cache file if it does not exist
        if not os.path.exists(os.path.join(CACHE_DIR, dir_clean)):
            with open(os.path.join(CACHE_DIR, dir_clean), "w") as f:
                log.debug(f"No cache for {dir}")
                f.write(dir_hash)
                cache_valid = False

        # Check if the hash is in the cache
        with open(os.path.join(CACHE_DIR, dir_clean), "r+") as f:
            # Hash does not match last - invalidate!
            if (old_hash := f.readline().strip()) != dir_hash:
                log.debug(f"Invalid cache for {dir} ({dir_hash} != {old_hash})")
                cache_valid = False
            else:
                log.debug(f"Valid cache for {dir} ({dir_hash})")

            # Update the hash
            f.seek(0)
            f.write(dir_hash)
            f.truncate()

    return cache_valid


def write_caches():
    """
    Write the caches to disk
    """
    for cache_name, cache_details in CACHE_CHECKS.items():
        with open(cache_details["cache_file"], "w") as f:
            log.debug(f"Writing image cache for {cache_name}")
            json.dump(cache_details["docker_cache"], f, indent=4)


# Cache validation logic
os.makedirs(CACHE_DIR, exist_ok=True)

for cache_name, cache_details in CACHE_CHECKS.items():
    # Check if the cache is valid
    if validate_dirs_cache(cache_details["directory"]):
        # Load the docker image cache file
        if os.path.exists(cache_details["cache_file"]):
            with open(cache_details["cache_file"], "r") as f:
                cache_details["docker_cache"] = json.load(f)
        else:
            log.debug(f"No docker image cache found for {cache_name}")

# Update globals
DOCKER_BENCHMARK_IMAGE_CACHE = CACHE_CHECKS["BENCHMARKS"]["docker_cache"]

# Fuzzer image cache only good if the benchmark cache is good
DOCKER_FUZZER_IMAGE_CACHE = (
    CACHE_CHECKS["FUZZERS"]["docker_cache"] if DOCKER_BENCHMARK_IMAGE_CACHE else {}
)
DOCKER_COMPILER_IMAGE_CACHE = CACHE_CHECKS["COMPILERS"]["docker_cache"]
