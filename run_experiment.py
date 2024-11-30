#!/usr/bin/env python3

import asyncio
import os
import time
import math
import argparse
import shutil
from itertools import islice
from typing import List

import pandas as pd
from tabulate import tabulate
from loguru import logger as log

from src.cache import write_caches
from src.experiments import (
    table_3_part_1,
    table_3_part_2,
    table_4,
    table_5,
    table_7_oscat_basic,
    table_7_oscat_network,
    cve,
)
from src.fuzzers import (
    BaseFuzzer,
    AFLPlusPlus,
    ICSFuzz,
    FieldFuzz,
    ICSQuartz,
    ICSQuartzScanCycleAware,
    ICSQuartzScanCycleMutators,
    ICSQuartzASANAlternative,
)


async def fuzz_targets(
    benchmarks: list,
    compiler: str,
    dry_run: bool,
    rerun_stats: bool,
    fuzz_trials: int,
    fuzz_time: int,
    fuzzers: list,
    concurrent_fuzzers: int,
    cpus: list,
    cpuset: str,
    results_dir: str,
    get_logs: bool,
):
    all_stats = []
    fuzzer_instances: List[BaseFuzzer] = []

    # 1 - Build all fuzzer images
    # TODO - make benchmark builds async (must build all benchmarks first, then fuzz targets)
    for benchmark in benchmarks:
        for fuzzer in fuzzers:
            log.info(f"Creating {fuzzer.fuzzer_name} experiments (n={fuzz_trials})...")
            for trial in range(fuzz_trials):
                fuzzer_instances.append(fuzzer(benchmark, trial, compiler))

    # Write docker image caches
    write_caches()

    log.info(f"Loaded {len(fuzzer_instances)} fuzzer trials!")
    log.info(
        f"This will take approximately {math.ceil(len(fuzzer_instances) / concurrent_fuzzers) * fuzz_time} seconds to complete."
    )

    if dry_run and not rerun_stats:
        log.info("Dry run mode enabled, stats disabled... Quitting!")
        return

    # Dry-run mode
    stats_exist = True if rerun_stats else False
    if dry_run is False:
        # Loop through experiments in batches
        batch_iter = iter(fuzzer_instances)
        experiment_count = 0
        while batch := list(islice(batch_iter, concurrent_fuzzers)):
            experiment_count += len(batch)
            log.info(
                f"Starting batch of {len(batch)} fuzzers... ({experiment_count}/{len(fuzzer_instances)})"
            )
            log.info(f"Allowing fuzzing for {fuzz_time} seconds")

            # 2 - Start all fuzzers
            start_fuzz_time = time.time()
            tasks = []
            for cpu_idx, fuzzer_instance in enumerate(batch):
                log.info(f"Starting {fuzzer_instance.fuzzer_name} fuzzer")
                tasks.append(
                    fuzzer_instance.start_fuzzer(cpus=[cpus[cpu_idx]], cpuset=cpuset)
                )
            await asyncio.gather(*tasks)

            # 3 - Allow fuzzing to run (subtracting time it took to launch all containers)
            sleep_time = fuzz_time - (time.time() - start_fuzz_time)
            log.info(
                f"All containers started! Sleeping for {sleep_time} more seconds to finish fuzzing."
            )
            if sleep_time > 0:
                time.sleep(sleep_time)

            # 4 - Stop all fuzzers
            tasks = []
            for fuzzer in batch:
                tasks.append(fuzzer.stop_fuzzer())
            await asyncio.gather(*tasks)
            log.info("All fuzzers stopped!")

        # 5.5 - Collect logs
        if get_logs:
            try:
                shutil.rmtree(".logs")
            except FileNotFoundError:
                pass
            tasks = []
            for fuzzer in fuzzer_instances:
                tasks.append(fuzzer.get_fuzzer_logs())
            await asyncio.gather(*tasks)

    # 5 - Collect stats from each fuzzer
    tasks = []
    stats_success = True
    for fuzzer in fuzzer_instances:
        tasks.append(fuzzer.get_fuzzer_stats(exist=stats_exist))
    try:
        results = await asyncio.gather(*tasks)
    except Exception as e:
        stats_success = False
        log.error(f"Error collecting stats: {e}")

    if not dry_run:
        # 6 - Remove all containers
        # TODO - condense these down
        tasks = []
        for fuzzer in fuzzer_instances:
            tasks.append(fuzzer.cleanup())
        await asyncio.gather(*tasks)

    if not stats_success:
        log.error("Stats collection failed. Exiting...")
        exit(1)

    for fuzzer, stats in zip(fuzzer_instances, results):
        # Store logs
        # TODO - make this a parameter
        # await fuzzer.get_fuzzer_logs()

        # Store stats
        stats["benchmark"] = fuzzer.benchmark_name
        stats["fuzzer"] = fuzzer.fuzzer_name
        stats["trial"] = fuzzer.trial_num
        stats["elapsed_time"] = fuzzer.get_fuzzer_elapsed_time()

        all_stats.append(stats)

    # 7 - Statistical Analysis
    results_timestamp = int(time.time())
    os.makedirs(results_dir, exist_ok=True)

    # 8 - CSV Stats
    df = pd.DataFrame(all_stats)

    # Data Cleanup
    columns = df.columns.tolist()
    columns.remove("fuzzer")
    columns.remove("benchmark")
    new_order = ["fuzzer", "benchmark"] + columns
    df = df[new_order]

    # Sort by fuzzer, then benchmark
    df = df.sort_values(by=["fuzzer", "benchmark"])

    # All stats
    df.to_csv(os.path.join(results_dir, f"{results_timestamp}-all.csv"), index=False)
    df.to_csv(os.path.join(results_dir, f"latest-all.csv"), index=False)

    # Standard deviation stats
    std_dev_stats = [
        "execs_per_sec",
        "execs_total",
        "first_crash_time",
        "first_crash_executions",
        "elapsed_time",
    ]

    # Averaged metrics (per benchmark)
    grouped = df.drop(columns=["trial"]).groupby(["fuzzer", "benchmark"])
    mean_stats = grouped.mean().reset_index()

    # Enrich with standard deviation
    for stat in std_dev_stats:
        if stat in mean_stats.columns:
            mean_stats[f"{stat}_std_dev"] = grouped[stat].std().reset_index()[stat]

    # Write to CSV
    mean_stats.to_csv(
        os.path.join(results_dir, f"{results_timestamp}-per-benchmark.csv"), index=False
    )
    mean_stats.to_csv(
        os.path.join(results_dir, f"latest-per-benchmark.csv"), index=False
    )

    # Averaged metrics (overall)
    grouped = df.drop(columns=["benchmark", "trial"]).groupby(["fuzzer"])
    mean_stats_overall = grouped.mean().reset_index()

    # Enrich with standard deviation
    for stat in std_dev_stats:
        mean_stats_overall[f"{stat}_std_dev"] = grouped[stat].std().reset_index()[stat]

    # Write to CSV
    mean_stats_overall.to_csv(
        os.path.join(results_dir, f"{results_timestamp}-overall.csv"), index=False
    )
    mean_stats_overall.to_csv(
        os.path.join(results_dir, f"latest-overall.csv"), index=False
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run fuzzing experiment.")
    parser.add_argument(
        "--fuzz-time", type=int, default=30, help="Time for fuzzing in seconds"
    )
    parser.add_argument(
        "--fuzz-trials",
        type=int,
        default=3,
        help="Number of fuzzing trials (per benchmark)",
    )
    parser.add_argument(
        "--cpus",
        type=str,
        default="1-59",
        help="Range of CPUs to use at once (e.g., 1-59).",
    )
    parser.add_argument(
        "--experiment",
        type=str,
        choices=[
            "table_3",
            "table_4",
            "table_5",
            "table_7",
            "cve",
            "build-all",
        ],
        required=True,
        help="The experiment set to run.",
    )
    parser.add_argument(
        "--cpus-isolated",
        action="store_true",
        help="Whether these CPUs have been isolated by the kernel scheduler.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build images but do not run.",
    )
    parser.add_argument(
        "--rerun-stats",
        action="store_true",
        help="Rerun stats collection for existing experiments.",
    )
    parser.add_argument(
        "--get-logs",
        action="store_true",
        help="Get container logs for existing experiments.",
    )
    args = parser.parse_args()

    # Rerun stats = dry run
    if args.rerun_stats:
        args.dry_run = True

    # Parse cpu range into list
    cpuset = args.cpus if args.cpus_isolated else None
    cpus = []
    if args.cpus:
        for part in args.cpus.split(","):
            if "-" in part:
                a, b = part.split("-")
                cpus.extend(range(int(a), int(b) + 1))
            else:
                cpus.append(int(part))
    concurrent_fuzzers = len(cpus)

    # Select the benchmark and compiler to use
    benchmark_configs = []
    dry_run = args.dry_run
    rerun_stats = args.rerun_stats
    match args.experiment:
        case "table_3":
            # These benchmarks prefer this configuration
            table_3_part_1["fuzzers"] = [ICSQuartzASANAlternative]
            benchmark_configs.append(table_3_part_1)

            # The rest of the benchmarks prefer regular configuration
            table_3_part_2["fuzzers"] = [ICSQuartz]
            benchmark_configs.append(table_3_part_2)

        case "table_4":
            table_4["fuzzers"] = [ICSQuartzScanCycleMutators, AFLPlusPlus, FieldFuzz, ICSFuzz]
            benchmark_configs.append(table_4)


        case "table_5":
            table_5["fuzzers"] = [ICSQuartzScanCycleMutators, ICSQuartzScanCycleAware]
            benchmark_configs.append(table_5)

        case "table_7":
            # All fuzzers can run oscat basic
            table_7_oscat_basic["fuzzers"] = [ICSQuartz, FieldFuzz, ICSFuzz]
            benchmark_configs.append(table_7_oscat_basic)

            # CODESYS does not support oscat network for 64bit
            table_7_oscat_network["fuzzers"] = [ICSQuartz]
            benchmark_configs.append(table_7_oscat_network)

        case "cve":
            cve["fuzzers"] = [ICSQuartz, FieldFuzz, ICSFuzz]
            benchmark_configs.append(cve)

        case "build-all":
            dry_run = True

            table_3_part_1["fuzzers"] = [ICSQuartzASANAlternative]
            table_3_part_2["fuzzers"] = [ICSQuartz]
            table_4["fuzzers"] = [ICSQuartzScanCycleMutators, AFLPlusPlus, FieldFuzz, ICSFuzz]
            table_5["fuzzers"] = [ICSQuartzScanCycleMutators, ICSQuartzScanCycleAware]
            table_7_oscat_basic["fuzzers"] = [ICSQuartz, FieldFuzz, ICSFuzz]
            table_7_oscat_network["fuzzers"] = [ICSQuartz]
            cve["fuzzers"] = [ICSQuartz, FieldFuzz, ICSFuzz]
            benchmark_configs.extend([table_3_part_1, table_3_part_2, table_4, table_5, table_7_oscat_basic, table_7_oscat_network, cve])

    # Run benchmark configs
    df_results = []
    for config in benchmark_configs:

        # TODO - potentially move fuzzers to config here

        fuzzers = config["fuzzers"]
        compiler = config["compiler"]
        benchmarks = config["benchmarks"]
        results = config["results"]
        results_columns = config["results_columns"]

        results_dir = f"results/{args.experiment}"

        # Fuzz
        asyncio.run(
            fuzz_targets(
                benchmarks,
                compiler,
                dry_run,
                rerun_stats,
                args.fuzz_trials,
                args.fuzz_time,
                fuzzers,
                concurrent_fuzzers,
                cpus,
                cpuset,
                results_dir,
                args.get_logs,
            )
        )

        # Fetch key results
        if not dry_run or args.rerun_stats:
            for result in results:
                df = pd.read_csv(os.path.join(results_dir, result))
                columns = []
                if "fuzzer" in df.columns:
                    columns.append("fuzzer")
                if "benchmark" in df.columns:
                    columns.append("benchmark")
                columns += results_columns

                df = df[columns]

                df_results.append(df)
        
    # Print results
    match args.experiment:
        case "table_3":
            df_all = pd.concat(df_results)
            # Cleanup icsquartz-asan-alt to icsquartz
            df_all["fuzzer"] = df_all["fuzzer"].replace("icsquartz-asan-alt", "icsquartz")
            print(f"Per-Benchmark Stats:")
            print(
                tabulate(
                    df_all,
                    headers=df.columns,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )

            df_mean = df_all.drop(columns=["fuzzer","benchmark"]).mean().reset_index().transpose()
            df_mean.columns = df_mean.iloc[0]  # Set the first row as the header
            df_mean = df_mean[1:]  # Remove the first row
            print("Average Stats:")
            print(
                tabulate(
                    df_mean,
                    headers=df_mean.columns,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )

        case "table_4":
            df = pd.concat(df_results)

            # Group by fuzzer/benchmark
            grouped = df.drop(columns=["trial"]).groupby(["fuzzer", "benchmark"])
            # Average out the stats
            mean_stats = grouped.mean().reset_index()
            # Count how many instances of vuln is found
            mean_stats["vuln_found"] = grouped["first_crash_time"].apply(lambda x: f'{(x.notnull().sum())}').values
            # Replace 0's with dashes for vuln_found
            mean_stats["vuln_found"] = mean_stats["vuln_found"].apply(lambda x: "-" if x == "0" else x)
            # Display benchmark names
            mean_stats["benchmark"] = mean_stats["benchmark"].apply(lambda x: x.replace("scan_cycle_", "").replace("_", " ").title())
            # Replace NaN with dashes
            mean_stats = mean_stats.fillna("-")
            # Replace vuln_found
            mean_stats["vuln_found"] = mean_stats["vuln_found"].apply(lambda x: x.replace("-", "0"))
            # Pivot table with fuzzer in column names
            mean_stats_pivoted = mean_stats.pivot_table(index="benchmark", columns="fuzzer", aggfunc="first")
            # Flatten MultiIndex in columns for easy access with fuzzer-specific suffixes.
            mean_stats_pivoted.columns = [f"{fuzzer}_{metric}" for metric, fuzzer in mean_stats_pivoted.columns]
            mean_stats_pivoted = mean_stats_pivoted.reset_index()
            # Select columns for viewing
            def all_fuzzers(stat: str, short=False) -> list:
                fuzzers = [
                    "icsquartz-scan-cycle-mutators" if not short else "icsquartz",
                    "aflplusplus",
                    "icsfuzz",
                    "fieldfuzz",
                ]
                return [(f"{fuzzer}_{stat}" if not short else f"{fuzzer} {stat}") for fuzzer in fuzzers]
            columns = [
                "benchmark",
                # General stats
                *all_fuzzers("vuln_found"),
                *all_fuzzers("first_crash_time"),
                *all_fuzzers("first_crash_executions"),
            ]
            df_display = mean_stats_pivoted[columns]

            headers = [
                "Benchmark",
                *all_fuzzers("Vuln Found", short=True),
                *all_fuzzers("First Crash Time", short=True),
                *all_fuzzers("First Crash Execs", short=True),
            ]

            print(
                tabulate(
                    df_display,
                    headers=headers,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )
        case "table_5":
            df = pd.concat(df_results)

            # Group by fuzzer/benchmark
            grouped = df.drop(columns=["trial"]).groupby(["fuzzer", "benchmark"])
            # Average out the stats
            mean_stats = grouped.mean().reset_index()
            # Count how many instances of vuln is found
            mean_stats["vuln_found"] = grouped["first_crash_time"].apply(lambda x: f'{(x.notnull().sum())}').values
            # Replace 0's with dashes for vuln_found
            mean_stats["vuln_found"] = mean_stats["vuln_found"].apply(lambda x: "-" if x == "0" else x)
            # Display benchmark names
            mean_stats["benchmark"] = mean_stats["benchmark"].apply(lambda x: x.replace("scan_cycle_", "").replace("_", " ").title())
            # Replace NaN with dashes
            mean_stats = mean_stats.fillna("-")
            # Replace vuln_found
            mean_stats["vuln_found"] = mean_stats["vuln_found"].apply(lambda x: x.replace("-", "0"))
            # Pivot table with fuzzer in column names
            mean_stats_pivoted = mean_stats.pivot_table(index="benchmark", columns="fuzzer", aggfunc="first")
            # Flatten MultiIndex in columns for easy access with fuzzer-specific suffixes.
            mean_stats_pivoted.columns = [f"{fuzzer}_{metric}" for metric, fuzzer in mean_stats_pivoted.columns]
            mean_stats_pivoted = mean_stats_pivoted.reset_index()
            mean_stats_pivoted

            # Add stale states %
            scan_cycle_aware = ["icsquartz-scan-cycle-mutators", "icsquartz-scan-cycle-aware"]
            for fuzzer in scan_cycle_aware:
                mean_stats_pivoted[f"{fuzzer}_stale_state"] = (mean_stats_pivoted[f"{fuzzer}_state_resets"] / mean_stats_pivoted[f"{fuzzer}_execs_total"])

            # Select columns for viewing
            def all_fuzzers(stat: str) -> list:
                fuzzers = [
                    "icsquartz-scan-cycle-mutators",
                    "icsquartz-scan-cycle-aware",
                ]
                return [f"{fuzzer}_{stat}" for fuzzer in fuzzers]

            columns = [
                "benchmark",

                # General stats
                *all_fuzzers("vuln_found"),
                *[f"{fuzzer}_stale_state" for fuzzer in scan_cycle_aware],
            ]
            df_display = mean_stats_pivoted[columns]
            print(
                tabulate(
                    df_display,
                    headers=columns,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )

        case "table_7":
            df = pd.concat(df_results)
            # Group by fuzzer/benchmark
            grouped = df.groupby(["fuzzer", "benchmark"])

            # Average out the stats
            mean_stats = grouped.mean().reset_index()

            # Pivot
            mean_stats_pivoted = mean_stats.pivot_table(index="benchmark", columns="fuzzer", aggfunc="first")

            # Flatten MultiIndex in columns for easy access with fuzzer-specific suffixes.
            mean_stats_pivoted.columns = [f"{fuzzer}_{metric}" for metric, fuzzer in mean_stats_pivoted.columns]

            # Reorder colunmns for icsquartz, fieldfuzz, icsfuzz
            mean_stats_pivoted = mean_stats_pivoted[["icsquartz_execs_total", "fieldfuzz_execs_total", "icsfuzz_execs_total"]]

            # Cleanup
            mean_stats_pivoted = mean_stats_pivoted.reset_index()
            mean_stats_pivoted = mean_stats_pivoted.fillna("-")

            print(
                tabulate(
                    mean_stats_pivoted,
                    headers=mean_stats_pivoted.columns,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )

        case "cve":
            df = pd.concat(df_results)

            print(
                tabulate(
                    df,
                    headers=df.columns,
                    tablefmt="heavy_outline",
                    showindex=False,
                )
            )
