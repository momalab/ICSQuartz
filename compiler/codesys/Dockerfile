# syntax=docker/dockerfile:1
FROM debian:buster

RUN apt-get update && \
    apt-get install -y \
        wget \
        unzip \
        libpthread-stubs0-dev

ENV DEBIAN_FRONTEND=noninteractive
ENV CODESYS_DOWNLOAD="https://store.codesys.com/ftp_download/3S/LinuxSL/2302000005/3.5.16.10/CODESYS%20Control%20for%20Linux%20SL%203.5.16.10.package"

# Download CODESYS and install it and the codemeter package
ENV TEMPDIR=/tmp
WORKDIR ${TEMPDIR}
RUN wget --output-document=codesys.package $CODESYS_DOWNLOAD && \
    unzip -p codesys.package '*.deb' > codesys.deb && \
    unzip -p codesys.package '*codemeter*.deb' > codemeter.deb && \
    apt install -y ${TEMPDIR}/codemeter.deb && \
    dpkg --force-confdef --force-confold -i codesys.deb && \
    rm -f codesys.package codesys.deb codemeter.deb

# Setup preconfigured config.
COPY ./configs/CODESYSControl.cfg /etc/CODESYSControl.cfg
COPY ./configs/CODESYSControl_User.cfg /etc/CODESYSControl_User.cfg
COPY locate-area-zero.sh /locate-area-zero.sh

ENV CODESYS_HOME=/var/opt/codesys/
ENV CODESYS_LOG=/wrapper.log

WORKDIR ${CODESYS_HOME}

COPY start.sh /start.sh
CMD [ "/bin/bash", "/start.sh" ]
