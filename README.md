# ICSQuartz

This project introduces ICSQuartz, a scan cycle-aware and vendor-agnostic fuzzer for Industrial Control Systems (ICS) [[1]](#cite-us).

## Cite us

Corban Villa, Constantine Doumanidis, Hithem Lamri, Prashant Hari Narayan Rajput and Michail Maniatakos, "ICSQuartz: Scan Cycle-Aware and Vendor-Agnostic Fuzzing for Industrial Control Systems" Network and Distributed System Security (NDSS) Symposium, 2025.

```
@inproceedings{icsquartz2025ndss,
  author    = {Villa, Corban and Doumanidis, Constantine and Lamri, Hithem and Rajput, Prashant Hari Narayan and Maniatakos, Michail},
  booktitle = {Network and Distributed System Security (NDSS) Symposium},
  title     = {ICSQuartz: Scan Cycle-Aware and Vendor-Agnostic Fuzzing for Industrial Control Systems},
  year={2025}
}
```

## Build Instructions

### Dependencies

1. A Linux System (validated on Ubuntu 22.04).
2. [Docker](https://docs.docker.com/engine/install/ubuntu/) (validated with 27.3.1).
3. [Python](https://github.com/pyenv/pyenv) (**requires** 3.10 or higher).
4. `git`, `pip`, `venv` (`sudo apt install -y git python3-pip python3-venv`).

### System Configuration

The experiment script (`run_experiment.py`) expects your user to have permission to execute `docker` commands without `sudo`. You can do this by adding your user to the `docker` group (i.e. `sudo usermod -aG docker $USER` and logout then login).
> 
> If a `docker` group does not exist, you may need to [add it manually](https://docs.docker.com/engine/install/linux-postinstall/) (i.e. `sudo groupadd docker`).
> 

To run experiments with FieldFuzz and ICSFuzz, you will need to disable ASLR:
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
> 
> This configuration will not persist across reboots. To re-enable ASLR, replace `0` with `2` or reboot your system.
> 

Calibrate the CODESYS virtual PLC to your system's specific configuration for ICSFuzz and FieldFuzz: `./scripts/calibrate-codesys.sh`.
>
> Ensure ASLR is disabled before running the calibration script. This must be run once per system and will store the respective details under `.config/codesys-area-zero`.
>

### ICSQuartz

First you will want to download the ICSQuartz repository to run the experiments. Install the requires Python packages as well:
```bash
git clone https://github.com/momalab/ICSQuartz.git icsquartz
cd ./icsquartz
python3 -m venv ./venv # Creates a virtual environment
source ./venv/bin/activate # Activates the virtual Python environment
pip install -r requirements.txt
```

## Reproducing Paper Results

### Reproducing Results (Tables III, IV, V, VII)
To reproduce the results shown in Tables III, IV, V, and VII, we include a script (`run_experiment.py`) in the main folder, which manages the benchmark build process and fuzzing campaign across multiple processors. The script allows you to adjust the following experiment parameters:

- Fuzz time: The time (in seconds) to fuzz each program binary.
- Fuzz trials: The number of times to repeat each fuzzing experiment to demonstrate statistical significance.
- CPUs: The specific cores available to allocate for fuzzing (e.g., `1-8`). One experiment will be allocated per core.
- Experiment: The specific experiment to reproduce (e.g., `table_3`, `table_4`, `table_5`, `table_7`, `cve`).

Configurations are passed to the script as command-line parameters:

```bash
./run_experiment.py --fuzz-time 180 --fuzz-trials 3 --cpus 1-8 --experiment table_3
```

Invoking the experiment script will automatically:

1. Build the ST compiler (defined in `compiler/`) and compile the program source into an instrumented binary.
2. Build fuzzing targets required for the experiment (defined in `scripts/experiment.py`) using the respective fuzzer (i.e. `icsquartz/Dockerfile`).
3. Create a queue of size: `fuzz_time × fuzz_trials × |benchmarks|`.
4. Execute jobs from the queue in batches of size: `cpus`.
5. Collect and aggregate statistics into `results/`.
6. The time required for the build stages will vary, and may take significantly longer for the first experiment as dependencies are downloaded and built in the containers.
​
### Run All Experiments (E1-E5)
You may run all 5 experiments by running: `./evaluate-all.sh`. The script will place results in `all-results.txt`, which can be interpreted using the experiment descriptions below.

### Experiment (E1)
**[Performance] | [Table III] | [10 human-minutes + 1.5 compute-hour]**

In this experiment, we reproduce the comparison with state-of-the-art fuzzers. The following parameters should require approximately 1 hour to fuzz all 17 benchmarks, though we encourage the evaluator to increase `fuzz_time` or `cpus` if more time and resources are available.

```bash
./run_experiment.py --fuzz-time 565 --fuzz-trials 3 --cpus 1-8 --experiment table_3
```
**Results:**
The key metrics to compare in this experiment are `execs_per_sec` and `first_crash_executions` (Table III). While we expect executions per second to vary significantly depending on the hardware, the inputs to first crash should not. An averaged breakdown per-benchmark, in addition to an overall average, are displayed.

### Experiment (E2)
**[Fuzzing Campaign] | [Table VII] | [10 human-minutes + 1.5 compute-hour]**

In this experiment, we reproduce the fuzzing campaign across the OSCAT Basic library using a subset of 18 benchmarks which result in crashes.

```bash
./run_experiment.py --fuzz-time 170 --fuzz-trials 3 --cpus 1-8 --experiment table_7
```

**Results:**
Key results of this experiment is the comparison of total executions between ICSQuartz, FieldFuzz, and ICSFuzz. As ICSQuartz is not tied to a scan cycle, total executions should outperform both FieldFuzz and ICSFuzz.

### Experiment (E3)
**[CVE] | [10 human-minutes + 0.2 compute-hour]**

In this experiment, we reproduce the [OSCAT Basic CVE](https://customers.codesys.com/index.php?eID=dumpFile&t=f&f=18601&token=27389a52e058d95ff70b17a2370fedf07e073034&download=) discovered.

```bash
./run_experiment.py --fuzz-time 500 --fuzz-trials 3 --cpus 1-8 --experiment cve
```

**Results:**
Key results of this experiment demonstrate the added precision of ICSQuartz for detecting memory vulnerabilities. A crash should be quickly detected by ICSQuartz, but will not be detected by FieldFuzz and ICSFuzz. This vulnerability is now patched in the latest version of OSCAT Basic.

### Experiment (E4)
**[Scan Cycle Fuzzing] | [Table IV] | [10 human-minutes + 0.2 compute-hour]**

In this experiment, we reproduce the ICSQuartz scan cycle fuzzing campaign across 12 benchmarks and compare it with related work.

```bash
./run_experiment.py --fuzz-time 500 --fuzz-trials 3 --cpus 1-8 --experiment table_4
```

**Results:**
The results demonstrate how ICSQuartz is able to locate vulnerabilities that can not be reliably detected by AFL++, FieldFuzz, or ICSFuzz.

### Experiment (E5): 
**[Scan Cycle Fuzzing] [Table V] [10 human-minutes + 0.2 compute-hour]**

In this experiment, we reproduce the ICSQuartz mutation strategy evaluation.

```bash
./run_experiment.py --fuzz-time 80 --fuzz-trials 3 --cpus 1-8 --experiment table_5
```

The `state_resets` metric indicates the number of times the scan cycle mutation algorithm intervened to reset stale execution paths. The higher number of `first_crash_executions` in these benchmarks reflects the stateful complexity introduced by ST programs tracking residual states.

## License

This project is licensed under the [CC BY-NC-SA 4.0 License](LICENSE).
