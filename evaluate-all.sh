#!/bin/bash
set -x

# Ensure venv
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    deactivate 2> /dev/null
    source venv/bin/activate
fi

# Ensure ASLR disabled
if [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]; then
    echo "You need to disable ASLR to run this experiment."
    exit 1
fi

echo "============================" >> all-results.txt
echo "Table III" >> all-results.txt
echo "============================" >> all-results.txt
./run_experiment.py --fuzz-time 565 --fuzz-trials 3 --cpus 1-8 --experiment table_3 >> all-results.txt

echo "============================" >> all-results.txt
echo "Table VII" >> all-results.txt
echo "============================" >> all-results.txt
./run_experiment.py --fuzz-time 170 --fuzz-trials 3 --cpus 1-8 --experiment table_7 >> all-results.txt

echo "============================" >> all-results.txt
echo "CVE" >> all-results.txt
echo "============================" >> all-results.txt
./run_experiment.py --fuzz-time 60 --fuzz-trials 1 --cpus 1-8 --experiment cve >> all-results.txt

echo "============================" >> all-results.txt
echo "Table IV" >> all-results.txt
echo "============================" >> all-results.txt
./run_experiment.py --fuzz-time 80 --fuzz-trials 3 --cpus 1-8 --experiment table_4 >> all-results.txt

echo "============================" >> all-results.txt
echo "Table V" >> all-results.txt
echo "============================" >> all-results.txt
./run_experiment.py --fuzz-time 80 --fuzz-trials 3 --cpus 1-8 --experiment table_5 >> all-results.txt
