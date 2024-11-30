# syntax=docker/dockerfile:1
FROM codesys-base

# Example to start a program on container startup
COPY --from=program codesys/Application/ ${CODESYS_HOME}/PlcLogic/Application/
COPY --from=program codesys/SysFileMap.cfg ${CODESYS_HOME}
