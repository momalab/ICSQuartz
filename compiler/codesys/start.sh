#!/bin/bash

set -x

cd $CODESYS_HOME

# Start CodeMeter (not starting will significantly slow CODESYS)
/usr/sbin/CodeMeterLin -f &

# Continually restart CODESYS (after crashes)
while true
do
        echo 'Starting CODESYS!'

        echo $(date +%s.%N)': Wrapper invoking CODESYS!' >> $CODESYS_LOG
        /opt/codesys/bin/codesyscontrol.bin -d /etc/CODESYSControl.cfg
        echo $(date +%s.%N)': Crash detected!' >> $CODESYS_LOG

        echo 'Wrapper: Restarting!'

        sleep 0.2
done
