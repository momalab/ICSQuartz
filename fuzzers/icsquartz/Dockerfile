# Stage 2 - Compile Fuzzer Target
FROM rust:1.76.0 AS icsquartz

# install sccache to cache subsequent builds of dependencies
RUN cargo install --locked sccache

ENV HOME=/root
ENV SCCACHE_CACHE_SIZE="1G"
ENV SCCACHE_DIR=$HOME/.cache/sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc && \
    mkdir ~/.cargo && \
    echo "[build]\nrustc-wrapper = \"${RUSTC_WRAPPER}\"" >> ~/.cargo/config

RUN rustup default nightly
RUN rustup component add rustfmt clippy

# Install clang 18, common build tools
ENV LLVM_VERSION=18
RUN apt update && apt install -y build-essential gdb git wget python3-venv ninja-build lsb-release software-properties-common gnupg cmake
# Workaround until https://github.com/llvm/llvm-project/issues/62475 is resolved
RUN set -ex &&\
    echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VERSION} main" > /etc/apt/sources.list.d/apt.llvm.org.list &&\
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key |  tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc &&\
    apt update &&\
    apt-get install -y clang-${LLVM_VERSION} lldb-${LLVM_VERSION} lld-${LLVM_VERSION} clangd-${LLVM_VERSION} clang-tidy-${LLVM_VERSION} clang-format-${LLVM_VERSION} clang-tools-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev lld-${LLVM_VERSION} lldb-${LLVM_VERSION} llvm-${LLVM_VERSION}-tools libomp-${LLVM_VERSION}-dev libc++-${LLVM_VERSION}-dev libc++abi-${LLVM_VERSION}-dev libclang-common-${LLVM_VERSION}-dev libclang-${LLVM_VERSION}-dev libclang-cpp${LLVM_VERSION}-dev libunwind-${LLVM_VERSION}-dev libclang-rt-${LLVM_VERSION}-dev libpolly-${LLVM_VERSION}-dev

# Setup LibAFL
WORKDIR /tmp
ENV LIBAFL_VERSION="7c95afc42fd5e418a6efad3f39122bb915c0a10c"
RUN wget https://github.com/AFLplusplus/LibAFL/archive/${LIBAFL_VERSION}.zip && \
    unzip ${LIBAFL_VERSION}.zip && \
    mv LibAFL-${LIBAFL_VERSION} /LibAFL && \
    rm -f ${LIBAFL_VERSION}.zip
WORKDIR /LibAFL

# Setup ICSQuartz
COPY ./Cargo.toml /icsquartz/Cargo.toml
COPY ./Cargo.lock /icsquartz/Cargo.lock
COPY ./src /icsquartz/src

WORKDIR /icsquartz
ARG SCAN_CYCLE="0"
ARG ASAN_ALT="0"

RUN cargo c && \
    if [ "$SCAN_CYCLE" -eq "1" ]; then \
        cargo build --release --features "scan_cycle scan_cycle_mutations"; \
    else \
        if [ "$ASAN_ALT" -eq "1" ]; then \
            cargo build --release --features "asan_crash_feedback"; \
        else \
            cargo build --release; \
        fi \
    fi

# Copy in the compiled PLC code
COPY --from=icsbuild /build /build
COPY --from=fuzztarget icsquartz/harness.c /build

ENV CC=/icsquartz/target/release/libafl_cc
ENV CXX=/icsquartz/target/release/libafl_cxx
ENV SRC=/build
ENV OUT=/out

ENV SEED=1
ENV CORES="2"
ENV FUZZ_TARGET=icsfuzz-demo

# Build the fuzz target
ARG CXXFLAGS=""
ARG LINKLIBS=""

WORKDIR ${OUT}

RUN $CXX $CXXFLAGS \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard \
    -L $SRC/libs/ \
    -v \
    -no-pie \
    $SRC/harness.* \
    -Wl,--allow-multiple-definition \
    -Wl,-Bstatic \
    $LINKLIBS \
    -lmain \
    -liec61131std \
    -lglibcWrappers \
    -Wl,-Bdynamic \
    -o $OUT/$FUZZ_TARGET && \
    chmod +x $OUT/$FUZZ_TARGET

COPY start-fuzz.sh .

CMD [ "/bin/bash", "start-fuzz.sh" ]
