# Stage 1 - Compile PLC Code
FROM ghcr.io/corbanvilla/rusty-address-sanitizer:address-sanitizer-x86_64

# We checkout the version of RuSTy with the compiler bug
WORKDIR /
ENV BUG_COMMIT="1b4a479f435a444124eca515d5d11c93e23e03f5"
RUN rm -rf /rusty && \
    mkdir /rusty && \
    git clone https://github.com/corbanvilla/rusty.git /rusty && \
    cd /rusty && \
    git checkout ${BUG_COMMIT} && \
    echo '\n[profile.dev]\npanic = "abort"\n[profile.release]\npanic = "abort"\n' >> ./libs/stdlib/Cargo.toml && \
    echo '\n[profile.dev]\npanic = "abort"\n[profile.release]\npanic = "abort"\n' >> ./Cargo.toml && \
    ./scripts/build.sh --build

ENV CXX="clang++-14"
ENV CXX_FLAGS="-g -fsanitize=address"
ENV PLC_EXTRA_FILES="/libs/wrappers/codesys/*.st /libs/wrappers/codesys/**/*.st /libs/wrappers/glibc_wrappers/*.st /rusty/libs/stdlib/iec61131-st/*.st /libs/oscat/*.st"

WORKDIR /libs
RUN cp -R /rusty/libs/stdlib/iec61131-st/ .
COPY ./libs/oscat/ ./oscat
COPY ./libs/wrappers/ ./wrappers

WORKDIR /build/libs

# IEC-61131 standard library
RUN cp /rusty/target/debug/libiec61131std.a .

# Compile GLIBC Wrappers
RUN ${CXX} ${CXX_FLAGS} \
        -c \
        -o /tmp/glibcWrappers.o \
        /libs/wrappers/glibc_wrappers/glibc_wrappers.cpp && \
    ar rcs \
        libglibcWrappers.a \
        /tmp/glibcWrappers.o

# Copy in PLC code
WORKDIR /build/src
COPY --from=fuzztarget src/* .

# Compile PLC code
WORKDIR /build/ir
RUN plc \
    --ir \
    -o main.ll \
    /build/src/**/*.st \
    ${PLC_EXTRA_FILES}

# Compile PLC to binary
WORKDIR /build/libs
RUN ${CXX} ${CXX_FLAGS} \
        -fsanitize-coverage=trace-pc-guard \
        -c \
        -o /tmp/main.o \
        /build/ir/main.ll && \
    ar rcs \
        libmain.a \
        /tmp/main.o
