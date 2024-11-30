import json
import shutil
import glob
import os

from loguru import logger as log

from src.containers import (
    copy_from_container,
)
from . import BaseFuzzer


class ICSQuartz(BaseFuzzer):
    """
    ICSQuartz class definition
    """

    fuzzer_name = "icsquartz"
    scan_cycle_aware = False
    scan_cycle_mutators = False
    fuzzer_caps = ["SYS_NICE"]

    async def start_fuzzer(self, cpus: list, cpuset=None):
        """
        Start fuzzing container instance
        """

        # Standard ASAN benchmarks (work well on most benchmarks)
        asan_options = {
            "halt_on_error": 1,
            "abort_on_error": 1,
            "exitcode": 0,
            "detect_leaks": 0,
            "malloc_context_size": 0,
            "symbolize": 0,
            "allocator_may_return_null": 1,
            "detect_odr_violation": 0,
            "handle_segv": 0,
            "handle_sigbus": 1,
            "handle_abort": 0,
            "handle_sigfpe": 0,
            "handle_sigill": 1,
            "print_summary": 0,
            "print_legend": 0,
            "print_full_thread_history": 0,
            "symbolize_inline_frames": 0,
        }

        # Some benchmarks perform better with these configurations
        if self.asan_alternate:
            asan_options["halt_on_error"] = 0
            asan_options["abort_on_error"] = 0
            asan_options["handle_sigbus"] = 0
            asan_options["handle_sigill"] = 0
            asan_options["log_path"] = "./asanlog"

        env_vars = {
            "CORES": ",".join([str(i) for i in cpus]),
            "SCAN_CYCLE_MAX": 10_000 if self.scan_cycle_aware else 2,
            "SCAN_CYCLE_ARGS": (
                ""
                if self.scan_cycle_mutators is False
                else "--state-resets --dynamic-scan-cycle"
            ),
            "MUTATOR_POWER": 4,
            "FUZZER_LOG": "fuzzer_log",
            "ASAN_OPTIONS": ":".join(
                [f"{key}={value}" for key, value in asan_options.items()]
            ),
            "MIN_INPUT_GENERATION": 128,
        }

        await super().start_fuzzer(env_vars=env_vars, cpuset=cpuset)

    async def get_fuzzer_stats(self, exist=False):
        """
        Returns execution metrics for fuzzer.
        """

        # TODO - abstract this to another function in the base class
        # Only pull from containers if exist is False
        if exist is False:

            # Remove the last used tempdir
            try:
                shutil.rmtree(self.results_tempdir)
            except FileNotFoundError:
                pass

            # Create a tempdir to store
            os.makedirs(self.results_tempdir, exist_ok=True)

            # Pull info from fuzzer
            try:
                await copy_from_container(
                    self.container_id, "/out/fuzzer_stats.json", self.results_tempdir
                )
                await copy_from_container(
                    self.container_id, "/out/crashes/", self.results_tempdir
                )
                await copy_from_container(
                    self.container_id, "/out/corpus/", self.results_tempdir
                )
            except Exception as e:
                log.error(f"Unable to copy files out from fuzzer: {e}")
                return {
                    "execs_per_sec": 0,
                    "execs_total": 0,
                    "first_crash_time": None,
                    "first_crash_executions": None,
                }

        # Parse the last line
        with open(os.path.join(self.results_tempdir, "fuzzer_stats.json"), "r") as f:
            # Store atleast 2 lines back (sometimes the most recent hasn't finished writing)
            last_last_line = ""
            last_line = ""
            while line := f.readline():
                last_last_line = last_line
                last_line = line

        # Load into json
        try:
            stats = json.loads(last_line)
        except json.JSONDecodeError:
            stats = json.loads(last_last_line)
        log.debug(f"Loaded stats: {stats}")

        # Executions / sec
        execs_per_sec = stats["exec_sec"]
        execs_total = stats["executions"]

        execs_total_alt = 0
        state_resets = 0
        try:
            # execs_total_alt is useful when using multi-core fuzzing.
            execs_total_alt = stats["client_stats"][1]["user_monitor"]["executions_"][
                "value"
            ]["Number"]
            state_resets = stats["client_stats"][1]["user_monitor"]["stale_state_"][
                "value"
            ]["Number"]
        except KeyError:
            pass

        # Parse all crashes
        crash_stats = []
        crashes = glob.glob(os.path.join(self.results_tempdir, "crashes/.*.metadata"))
        for crash in crashes:
            with open(crash, "r") as f:
                stats = json.loads(f.read())

            executions = stats["executions"]

            # calc time to find by execs_per_sec * executions
            if execs_per_sec == 0:
                time_to_find = None
            else:
                time_to_find = executions / execs_per_sec

            crash_stats.append({"exec_time": time_to_find, "executions": executions})

        # Sort by executions (asc)
        crash_stats.sort(key=lambda x: x["executions"])

        # Extract first crash
        first_crash_time = None
        first_crash_executions = None
        if len(crash_stats) > 0:
            first_crash_time = crash_stats[0]["exec_time"]
            first_crash_executions = crash_stats[0]["executions"]

        # TODO - these results should be standardized to a dataclass
        return {
            "execs_per_sec": execs_per_sec,
            "execs_total": max(
                execs_total,
                execs_total_alt,  # sometimes execs_total is wrong (TODO - investigate)
            ),
            # 'execs_total_alt': execs_total_alt,
            "first_crash_time": first_crash_time,
            "first_crash_executions": first_crash_executions,
            "state_resets": state_resets,
        }


class ICSQuartzScanCycleAware(ICSQuartz):
    """
    ICSQuartzScanCycle class definition

    Identical to ICSQuartz, but with scan cycle enabled.
    """

    fuzzer_name = "icsquartz-scan-cycle-aware"
    scan_cycle_aware = True
    scan_cycle_mutators = False

    @property
    def fuzzer_context(self):
        """
        Returns the context for the fuzzer
        """
        return os.path.join(self.fuzzers_dir, super().fuzzer_name)


class ICSQuartzScanCycleMutators(ICSQuartz):
    """
    ICSQuartzScanCycleMutators to enable dynamic scan cycle mutators
    """

    fuzzer_name = "icsquartz-scan-cycle-mutators"
    scan_cycle_aware = True
    scan_cycle_mutators = True

    @property
    def fuzzer_context(self):
        """
        Returns the context for the fuzzer
        """
        return os.path.join(self.fuzzers_dir, super().fuzzer_name)


class ICSQuartzASANAlternative(ICSQuartz):
    """
    ICSQuartzASANAlternative to enable ASAN alternative configurations
    """

    fuzzer_name = "icsquartz-asan-alt"
    asan_alternate = True

    @property
    def fuzzer_context(self):
        """
        Returns the context for the fuzzer
        """
        return os.path.join(self.fuzzers_dir, super().fuzzer_name)
