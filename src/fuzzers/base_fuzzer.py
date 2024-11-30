import os
import time

from loguru import logger as log

from src.config import (
    BENCHMARKS_DIR,
    COMPILER_DIR,
    FUZZERS_DIR,
    CODESYS_IMAGE,
    CODESYS_CONTEXT,
)
from src.cache import (
    DOCKER_FUZZER_IMAGE_CACHE,
    DOCKER_BENCHMARK_IMAGE_CACHE,
    DOCKER_COMPILER_IMAGE_CACHE,
)
from src.containers import (
    build_image,
    start_container,
    stop_container,
    remove_container,
    copy_from_container,
    get_container_logs,
)


class BaseFuzzer:
    """
    Base class definition for fuzzers.
    """

    # All class configurations
    fuzzers_dir = FUZZERS_DIR

    # Docker syscaps
    fuzzer_caps = []

    # Allows for stat-reruns to not fail
    fuzzer_start_time = -1
    fuzzer_stop_time = -1
    fuzzer_name = None

    # Arguments for fuzzer
    fuzzer_inputs = "/out/inputs"
    fuzzer_corpus = "/out/corpus"

    # Benchmark building
    build_benchmarks = True
    plc_compiler_version = None
    codesys_based = False  # TODO - change this to an enum and match on it
    codesys_area_zero = None

    # ICSQuartz Fuzzers (TODO - refactor these out!)
    scan_cycle_aware = False
    scan_cycle_mutators = False
    asan_alternate = False  # TODO - remove this from the base class

    benchmark_build_args = {}

    def __init__(
        self,
        benchmark_name: str,
        trial_num: int,
        compiler_version: str = "latest",
    ):
        """
        Build the image for this fuzzer to run
        """
        # Store important vars
        self.benchmark_name = benchmark_name
        self.trial_num = trial_num
        self.plc_compiler_version = compiler_version

        # Build the benchmark image if not existing
        if (
            not self.codesys_based
            and self.benchmark_image_name not in DOCKER_BENCHMARK_IMAGE_CACHE
        ):
            log.debug(f"Building benchmark image: {self.image_name}")
            contexts = self.__get_build_contexts(benchmark_name)
            build_image(
                self.benchmark_image_name,
                COMPILER_DIR,
                additional_contexts=contexts,
                dockerfile=f"{COMPILER_DIR}/{compiler_version}.Dockerfile",
            )
            DOCKER_BENCHMARK_IMAGE_CACHE[self.benchmark_image_name] = True
        elif self.codesys_based and CODESYS_IMAGE not in DOCKER_COMPILER_IMAGE_CACHE:
            log.debug(f"Building CODESYS Image: {CODESYS_IMAGE}")
            build_image(CODESYS_IMAGE, CODESYS_CONTEXT)
            DOCKER_COMPILER_IMAGE_CACHE[CODESYS_IMAGE] = True

        # Check if fuzzer image already exists
        if self.image_name in DOCKER_FUZZER_IMAGE_CACHE:
            log.debug(f"Reusing existing image: {self.image_name}")
            return

        # Build the fuzzer image
        build_args = {
            "SCAN_CYCLE": 0 if self.scan_cycle_aware is False else 1,
            "ASAN_ALT": 0 if self.asan_alternate is False else 1,
            "CODESYS_AREA_ZERO": self.codesys_area_zero if self.codesys_area_zero else 0,
        }
        build_args |= self.benchmark_build_args
        contexts = self.__get_build_contexts(benchmark_name, compiler_version)
        build_image(
            self.image_name,
            self.fuzzer_context,
            additional_contexts=contexts,
            build_args=build_args,
        )
        DOCKER_FUZZER_IMAGE_CACHE[self.image_name] = True

    async def start_fuzzer(
        self, cpus: list = None, cpuset: str = None, env_vars: dict = {}
    ):
        """
        Start fuzzing container instance
        """
        # TODO - do something with CPUs here if needed!

        env_vars["FUZZER_INPUTS"] = self.fuzzer_inputs
        env_vars["FUZZER_CORPUS"] = self.fuzzer_corpus
        env_vars["SEED"] = self.trial_num

        self.container_id = await start_container(
            f"{self.image_name}",
            caps=self.fuzzer_caps,
            cpuset=cpuset,
            env_vars=env_vars,
        )
        self.fuzzer_start_time = time.time()

    async def stop_fuzzer(self):
        """
        Stop fuzzing container instance
        """
        await stop_container(self.container_id)
        self.fuzzer_stop_time = time.time()

    def get_fuzzer_elapsed_time(self):
        """
        Returns the elapsed time of the fuzzer
        """
        if self.fuzzer_start_time is None or self.fuzzer_stop_time is None:
            raise ValueError("Fuzzer has not been started or stopped")

        return self.fuzzer_stop_time - self.fuzzer_start_time

    async def get_fuzzer_stats(self, exist=False):
        """
        Returns stats specific for a fuzzer.
        """
        pass

    async def get_fuzzer_logs(self):
        """
        Returns the logs of the fuzzer
        """
        log_dir = f".logs/{self.fuzzer_name}/{self.benchmark_name}/{self.trial_num}"
        os.makedirs(log_dir, exist_ok=True)

        program_log_path = os.path.join(log_dir, "program.log")
        fuzzer_stdout_log_path = os.path.join(log_dir, "fuzzer.stdout.log")
        fuzzer_stderr_log_path = os.path.join(log_dir, "fuzzer.stderr.log")

        # Remove existing logfiles
        try:
            os.remove(program_log_path)
        except FileNotFoundError:
            pass
        try:
            os.remove(fuzzer_stdout_log_path)
        except FileNotFoundError:
            pass
        try:
            os.remove(fuzzer_stderr_log_path)
        except FileNotFoundError:
            pass

        # Copy program out
        try:
            await copy_from_container(
                self.container_id, "/out/fuzzer_log", program_log_path
            )
        except Exception as e:
            log.error(
                f"Unable to fetch fuzzer_log from container ({self.container_id})"
            )
            pass

        # Copy docker out
        fuzzer_stdout, fuzzer_stderr = await get_container_logs(self.container_id)
        with open(fuzzer_stdout_log_path, "w+") as f:
            f.write(fuzzer_stdout)
        with open(fuzzer_stderr_log_path, "w+") as f:
            f.write(fuzzer_stderr)

    async def cleanup(self):
        """
        Ensure the container is stopped when the object is deleted
        """
        if hasattr(self, "container_id"):
            log.debug(f"Removing container {self.container_id} ({self.fuzzer_name})")
            await remove_container(self.container_id)

    def __get_build_contexts(self, benchmark_name, compiler_version=None):
        """
        Returns a Docker build context for a given benchmark.
        """
        contexts = {
            "fuzztarget": os.path.join(BENCHMARKS_DIR, benchmark_name),
        }

        # Also include benchmark image when specified
        if self.plc_compiler_version:
            contexts["icsbuild"] = (
                f"docker-image://plc-compiler-{compiler_version}:{benchmark_name}"
            )

        if self.codesys_based:
            contexts["codesys-base"] = f"docker-image://{CODESYS_IMAGE}"

        return contexts

    @property
    def results_tempdir(self):
        """
        Returns the temporary directory for fuzzer results
        """
        return f".results/{self.fuzzer_name}/{self.benchmark_name}/{self.trial_num}"

    @property
    def image_name(self):
        """
        Returns the image name for the fuzzer/benchmark pair
        """
        return f"{self.fuzzer_name}:{self.benchmark_name}"

    @property
    def benchmark_image_name(self):
        """
        Returns the image name for the benchmark
        """
        return f"plc-compiler-{self.plc_compiler_version}:{self.benchmark_name}"

    @property
    def fuzzer_context(self):
        """
        Returns the context for the fuzzer
        """
        return os.path.join(self.fuzzers_dir, self.fuzzer_name)
