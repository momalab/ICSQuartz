FROM aflplusplus/aflplusplus

RUN mkdir /fuzzing
WORKDIR /fuzzing
RUN mkdir input
RUN mkdir output
RUN echo 1 > ./input/seed

COPY --from=icsbuild /build /build
COPY --from=fuzztarget icsquartz/harness.c /build

ENV SRC=/build
ENV OUT=/out
ENV FUZZ_TARGET=icsfuzz-demo

WORKDIR ${OUT}

RUN afl-clang-fast++ \
    -O1 \
    -fno-omit-frame-pointer \
    -stdlib=libc++ \
    -v \
    -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard \
    $SRC/harness.* \
    -L $SRC/libs \
    -lmain \
    -liec61131std \
    -lglibcWrappers \
    -L/AFLplusplus \
    -lAFLDriver \
    -o ./${FUZZ_TARGET}

COPY start-fuzz.sh .

CMD [ "/bin/bash", "start-fuzz.sh" ]

