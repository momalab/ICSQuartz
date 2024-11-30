import os
import asyncio
import subprocess

from loguru import logger as log


async def start_container(
    image_name: str, caps: list = [], cpuset: str = None, env_vars={}
):
    """
    Runs a fuzzing container
    """

    log.info(f"Running {image_name} container")
    try:
        # Base run command
        command = ["docker", "run", "-d", "--restart", "unless-stopped"]

        # CPUSet:
        if cpuset:
            command.extend(["--cpuset-cpus", cpuset])

        # Add capabilities
        for cap in caps:
            command.extend(["--cap-add", cap])

        # Add environment variables
        for key, value in env_vars.items():
            command.extend(["-e", f"{key}={value}"])

        command.append(image_name)

        log.debug(f"Running command: {' '.join(command)}")

        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(f"Error running {image_name} container: {stderr.decode()}")

        container_id = stdout.decode().strip()

        log.info(f"{image_name} container ran successfully (ID: {container_id})")

    except Exception as e:
        log.error(f"Error running {image_name} container: {e}")
        raise e

    return container_id


async def stop_container(container_id: str):
    """
    Kills a running container immediately.
    """
    log.info(f"Stopping container {container_id}")
    try:
        process = await asyncio.create_subprocess_exec(
            *["docker", "stop", "-s", "9", container_id],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(
                f"Error stopping {container_id} container: {stderr.decode()}"
            )
        log.info(f"Container {container_id} stopped successfully")

    except Exception as e:
        log.error(f"Error stopping container {container_id}: {e}")
        raise e


def build_image(
    image_name: str,
    context: str,
    additional_contexts={},
    dockerfile: str = None,
    build_args={},
):
    """
    Build a Docker image from a Dockerfile
    """

    log.info(f"Building {image_name} image")
    try:
        # Base build command
        command = ["docker", "build", context, "-t", image_name]

        # Dockerfile
        if dockerfile:
            command.extend(["--file", dockerfile])

        # Add build contexts if included
        for key, value in additional_contexts.items():
            command.extend(["--build-context", f"{key}={value}"])

        # Add build args if included
        for key, value in build_args.items():
            command.extend(["--build-arg", f"{key}={value}"])

        log.debug(f"Running command: {' '.join(command)}")

        # Debugging
        subprocess.run(command, check=True, text=True)

        # process = await asyncio.create_subprocess_exec(
        #     *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        # )
        # stdout, stderr = await process.communicate()
        # if process.returncode != 0:
        #     raise Exception(f"Error building {image_name} image: {stderr.decode()}")

        log.info(f"{image_name} image built successfully")

    except Exception as e:
        log.error(f"Error building {image_name} image: {e}")
        raise e


def run_in_container(container_id: str, command: list) -> str:
    """
    Run a command in a running container
    """
    log.info(f"Running command {command} in container {container_id}")
    try:
        command_out = subprocess.run(
            ["docker", "exec", container_id] + command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    except Exception as e:
        log.error(f"Error running command {command} in container {container_id}: {e}")
        raise e

    return command_out.stdout


def read_from_stopped_container(container_id: str, file: str) -> str:
    """
    Copy a file from a stopped container
    """
    log.info(f"Copying {file} from container {container_id}")
    try:
        # Store the file temporarily to a local file
        outfile = "/tmp/.tempfile-fuzzer-stats"
        subprocess.run(
            ["docker", "cp", f"{container_id}:{file}", outfile],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with open(outfile, "r") as f:
            data = f.read()

        # Remove the tempfile
        os.remove(outfile)

    except Exception as e:
        log.error(f"Error copying {file} from container {container_id}: {e}")
        raise e

    return data


async def copy_from_container(container_id: str, src: str, dest: str):
    """
    Copy a file or directory from a container
    """
    log.info(f"Copying {src} from container {container_id} to {dest}")
    try:
        # subprocess.run(["docker", "cp", f"{container_id}:{src}", dest], check=True)
        process = await asyncio.create_subprocess_exec(
            *["docker", "cp", f"{container_id}:{src}", dest],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(
                f"Error copying {src} from container {container_id}: {stderr.decode()}"
            )

    except Exception as e:
        log.error(f"Error copying {src} from container {container_id}: {e}")
        raise e


async def remove_container(container_id: str):
    """
    Remove a container
    """
    log.info(f"Removing container {container_id}")
    try:
        # subprocess.run(
        #     ["docker", "rm", "--force", container_id],
        #     check=True,
        #     text=True,
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        # )
        process = await asyncio.create_subprocess_exec(
            *["docker", "rm", "--force", container_id],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(
                f"Error removing container {container_id}: {stderr.decode()}"
            )
        log.info(f"Container {container_id} removed successfully")

    except Exception as e:
        log.error(f"Error removing container {container_id}: {e}")
        raise e


async def get_container_logs(container_id: str):
    """
    Get the logs of a container
    """
    log.info(f"Getting logs for container {container_id}")
    try:
        # logs = subprocess.run(
        #     ["docker", "logs", container_id],
        #     check=True,
        #     text=True,
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        # )
        process = await asyncio.create_subprocess_exec(
            *["docker", "logs", container_id],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(
                f"Error getting logs for container {container_id}: {stderr.decode()}"
            )
        log.info(f"Logs for container {container_id} retrieved successfully")

    except Exception as e:
        log.error(f"Error getting logs for container {container_id}: {e}")
        raise e

    return stdout.decode(), stderr.decode()
