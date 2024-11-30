import os
import shutil

from loguru import logger as log

from src.containers import (
    copy_from_container,
)


from . import BaseFuzzer


class FieldFuzz(BaseFuzzer):
    """
    FieldFuzz class definition
    """

    fuzzer_name = "fieldfuzz"
    fuzzer_caps = ["SYS_NICE"]

    codesys_based = True

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
                icsfuzz_inputs_file = "/fuzzer_stats.log"
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
        first_crash_time = None
        first_crash_executions = None
        try:
            with open(os.path.join(self.results_tempdir, "fuzzer_stats.log"), "r") as f:
                while line := f.readline():
                    total_execs += 1

                    # Set start time on first iteration
                    if start_time == 0:
                        start_time = float(line.split(":")[0])

                    # Continually set end time
                    if line and ":" in line:
                        # Set end time on last iteration
                        end_time = float(line.split(":")[0])

                    # Get crashes
                    if first_crash_time is None and "Crashes: 1" in line:
                        first_crash_executions = total_execs
                        first_crash_time = float(line.split(":")[0]) - start_time
                        if f"Iteration: #{total_execs}" not in line:
                            log.error(
                                f"Crash detected at {first_crash_time} but mismatched iteration (expected {total_execs}):\n{line}"
                            )

        except FileNotFoundError:
            pass

        total_time = end_time - start_time

        execs_per_sec = total_execs / total_time if total_time > 0 else 0

        return {
            "execs_per_sec": execs_per_sec,
            "execs_total": total_execs,
            "first_crash_time": first_crash_time,
            "first_crash_executions": first_crash_executions,
        }
