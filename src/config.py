import os

BENCHMARKS_DIR = "benchmarks"
COMPILER_DIR = "compiler"
FUZZERS_DIR = "fuzzers"

CODESYS_IMAGE = "codesys-fuzz-base"
CODESYS_CONTEXT = "compiler/codesys"

# check if exists
CODESYS_AREA_ZERO = "0x7ffff53da000"
if os.path.exists(".config/codesys-area-zero"):
    CODESYS_AREA_ZERO = open(".config/codesys-area-zero").read().strip()
