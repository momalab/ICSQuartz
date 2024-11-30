import json
import shutil
import glob
import os

from loguru import logger as log

from src.containers import copy_from_container
from src.fuzzers import BaseFuzzer


class AFLPlusPlus(BaseFuzzer):
    """
    AFLPlusPlus Fuzzer class definition and stat extraction
    """

    fuzzer_name = "aflplusplus"
    fuzzer_caps = []

    async def get_fuzzer_stats(self, exist=False):

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
                    self.container_id,
                    os.path.join(self.fuzzer_corpus, "default/fuzzer_stats"),
                    self.results_tempdir,
                )
                await copy_from_container(
                    self.container_id,
                    os.path.join(self.fuzzer_corpus, "default/crashes"),
                    self.results_tempdir,
                )
                await copy_from_container(
                    self.container_id,
                    os.path.join(self.fuzzer_corpus, "default/queue"),
                    self.results_tempdir,
                )
            except Exception as e:
                log.error(f"Unable to copy files out from fuzzer: {e}")
                return {}

        # Read the fuzzer stats
        try:
            with open(os.path.join(self.results_tempdir, "fuzzer_stats")) as f:
                stats_file_lines = f.read().splitlines()
        except FileNotFoundError:
            log.error("No fuzzer stats file found")
            # TODO - create a default not found stats file
            return {}
        stats_file_dict = {}
        for stats_line in stats_file_lines:
            key, value = stats_line.split(": ")
            stats_file_dict[key.strip()] = value.strip()

        fuzzer_run_time = int(stats_file_dict.get("run_time", 1)) or 1
        fuzzer_execs_total = int(stats_file_dict.get("execs_done", 1))
        fuzzer_execs_per_sec_alt = fuzzer_execs_total / fuzzer_run_time
        fuzzer_execs_per_sec = float(stats_file_dict.get("execs_per_sec", 1))

        # TODO - check if execs_per_sec is a moving average... I am pretty sure it is -Corban
        # print(f"AFL Alt Exec:")
        # print(fuzzer_execs_per_sec, fuzzer_execs_per_sec_alt)

        # Parse all crashes
        crash_stats = []
        crashes = glob.glob(os.path.join(self.results_tempdir, "crashes/id*"))
        for crash in crashes:
            # example crash file: `id:000000,sig:06,src:000000,time:12,execs:10,op:quick,pos:1`
            stats = {
                key: value
                for key, value in [stat.split(":") for stat in crash.split(",")]
            }

            executions = stats["execs"]
            time_to_find = stats["time"]

            crash_stats.append({"exec_time": time_to_find, "executions": executions})

        # Sort by executions (asc)
        crash_stats.sort(key=lambda x: x["executions"])

        # Extract first crash
        first_crash_time = None
        first_crash_executions = None
        if len(crash_stats) > 0:
            first_crash_time = int(crash_stats[0]["exec_time"]) / 1000
            first_crash_executions = int(crash_stats[0]["executions"])

        return {
            "execs_per_sec": fuzzer_execs_per_sec_alt,
            "execs_total": fuzzer_execs_total,
            "first_crash_time": first_crash_time,
            "first_crash_executions": first_crash_executions,
        }
