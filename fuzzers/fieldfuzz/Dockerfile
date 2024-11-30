# syntax=docker/dockerfile:1
FROM codesys-base

RUN apt update && \
    apt install -y curl python2-minimal build-essential && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python2 get-pip.py && \
    rm -f get-pip.py

COPY requirements.txt /root/requirements.txt

RUN pip install -r /root/requirements.txt

COPY pycodesys-master /pycodesys-master

WORKDIR /pycodesys-master/iec_fuzzer

# Copy in target from build context
COPY --from=fuzztarget codesys/Application/ ${CODESYS_HOME}/PlcLogic/Application/
COPY --from=fuzztarget codesys/SysFileMap.cfg ${CODESYS_HOME}
COPY --from=fuzztarget fieldfuzz/harness.json ./profiles/

COPY start-fuzz.sh /pycodesys-master/iec_fuzzer/

CMD [ "/bin/bash", "start-fuzz.sh" ]
