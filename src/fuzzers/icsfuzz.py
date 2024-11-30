import os
import shutil

from loguru import logger as log

from src.config import CODESYS_AREA_ZERO
from src.containers import (
    copy_from_container,
)


from . import BaseFuzzer


class ICSFuzz(BaseFuzzer):
    """
    ICSFuzz class definition
    """

    fuzzer_name = "icsfuzz"
    fuzzer_caps = ["SYS_NICE", "SYS_PTRACE"]
    codesys_based = True
    scan_cycle_ms = 35  # 15 ms~matches the approximate speed in ICSFuzz
    codesys_area_zero = CODESYS_AREA_ZERO
    benchmark_build_args = {"SCAN_CYCLE_MS": scan_cycle_ms}

    async def get_fuzzer_stats(self, exist=False):
        """
        Returns execution metrics for fuzzer.
        """

        if exist is False:

            # Remove the last used tempdir
            try:
                shutil.rmtree(self.results_tempdir)
            except FileNotFoundError:
                pass

            # Create a tempdir to store
            os.makedirs(self.results_tempdir, exist_ok=True)

            try:
                # Pull Crashes
                codesys_logs_file = "/wrapper.log"
                await copy_from_container(
                    self.container_id, codesys_logs_file, self.results_tempdir
                )

                # Pull All Inputs
                icsfuzz_inputs_file = "/icsfuzz.log"
                await copy_from_container(
                    self.container_id, icsfuzz_inputs_file, self.results_tempdir
                )

            except Exception as e:
                log.error(f"Error: {e}")
                return {}

        # Read all execs
        total_execs = 0
        total_time = None
        start_time = 0
        end_time = 0
        all_exec_times = []
        try:
            with open(os.path.join(self.results_tempdir, "icsfuzz.log"), "r") as f:
                while line := f.readline():
                    total_execs += 1

                    if ";" in line:
                        all_exec_times.append(float(line.split(";")[0]))

                    # Set start time on first iteration
                    if start_time == 0:
                        start_time = float(line.split(";")[0])

                    # Continually set end time
                    if line and ";" in line:
                        # Set end time on last iteration
                        end_time = float(line.split(";")[0])
        except FileNotFoundError:
            pass

        total_time = end_time - start_time

        # Read all crashes
        # TODO - inputs to first crash
        first_crash_time = None
        first_crash_executions = None
        try:
            with open(os.path.join(self.results_tempdir, "wrapper.log"), "r") as f:
                while line := f.readline():
                    if first_crash_time is None and "Crash detected" in line:

                        actual_time = float(line.split(":")[0])
                        first_crash_time = actual_time - start_time

                        # first crash executions is the number of all_exec_times before the first crash
                        first_crash_executions = len(
                            list(filter(lambda x: x < actual_time, all_exec_times))
                        )

                        break
        except FileNotFoundError:
            pass

        execs_per_sec = total_execs / total_time if total_time > 0 else 0

        return {
            "execs_per_sec": execs_per_sec,
            "execs_total": total_execs,
            "first_crash_time": first_crash_time,
            "first_crash_executions": first_crash_executions,
        }

    @property
    def image_name(self):
        """
        Append the scan cycle speed to differentiate images.
        """
        return f"{super().image_name}_scan_{self.scan_cycle_ms}_ms"
