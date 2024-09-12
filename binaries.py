"""Github Action Build

This file is used to build and distribute the safety binary on Github actions.
Take a look at the corresponding main.yml as well.

"""
import os
import subprocess
import sys
from collections import OrderedDict
from typing import Generator, Tuple

class Environment:
    """
    Environment class to handle the build and distribution process for different operating systems.
    """

    WIN = "win"
    LINUX = "linux"
    MACOS = "macos"

    def __init__(self) -> None:
        """
        Initialize the environment based on the BINARY_OS environment variable.
        """
        os_mapping = {
            "windows-latest": self.WIN,
            "ubuntu-20.04": self.LINUX,
            "macos-latest": self.MACOS
        }
        self.os = os_mapping[os.getenv("BINARY_OS")]

    @property
    def python(self) -> Generator[Tuple[int, str], None, None]:
        """
        Generator to yield the architecture and corresponding Python executable path.

        Yields:
            Generator[Tuple[int, str], None, None]: Architecture and Python executable path.
        """
        for arch, python in self.PYTHON_BINARIES[self.os].items():
            yield arch, python

    WIN_BASE_PATH = "C:\\hostedtoolcache\\windows\\Python\\3.10.11"

    PYTHON_BINARIES = {
        WIN: {
            64: f"{WIN_BASE_PATH}\\x64\\python.exe",  # setup-python default
            32: f"{WIN_BASE_PATH}\\x86\\python.exe"
        },

        # Order is important. If the 32 bit release gets built first,
        # you'll run into permission problems due to docker clobbering
        # up the current working directory.
        LINUX: OrderedDict([
            (64, "python3"),
        ]),

        MACOS: {
            64: "python3",
        }
    }

    def run(self, command: str) -> None:
        """
        Runs the given command via subprocess.run.

        Args:
            command (str): The command to run.

        Exits:
            Exits with -1 if the command wasn't successful.
        """
        try:
            print(f"RUNNING: {command}")
            print("-" * 80)
            result = subprocess.run(command, shell=True, check=True,
                                    stdout=subprocess.PIPE)
            if result:
                print(result.stdout.decode('utf-8').strip())
        except subprocess.CalledProcessError as e:
            print(f"ERROR calling '{command}'")
            print("-" * 20)
            print(e.output and e.output.decode('utf-8'))
            sys.exit(-1)

    def install(self) -> None:
        """
        Install required dependencies
        """
        for arch, python in self.python:
            self.run(f"{python} -m pip install pyinstaller")
            self.run(f"{python} -m pip install -r test_requirements.txt")

    def dist(self) -> None:
        """
        Runs PyInstaller to produce a binary for every platform architecture.
        """
        for arch, python in self.python:

            # Build the binary
            build_path = os.path.join("dist", f"safety-{arch}")
            self.run(f"{python} -m PyInstaller safety.spec"
                     f" --distpath {build_path}")

            # There seems to be no way to tell pyinstaller the binary name.
            # This leads to problems with artifact collector because
            # every binary is named the same.
            #
            # Move them around so they can be picked up correctly
            #
            artifact_path = os.path.join(
                os.getcwd(),
                "dist",
                f"safety-{self.os}-{'i686' if arch == 32 else 'x86_64'}"
            )
            binary_path = os.path.join(os.getcwd(), build_path, "safety")
            if self.os == self.WIN:
                self.run(f"move {binary_path}.exe {artifact_path}.exe")
            else:
                self.run(f"cp {binary_path} {artifact_path}")

    def test(self) -> None:
        """
        Runs tests for every available architecture on the current platform.
        """
        for arch, python in self.python:
            self.run(f"{python} -m pytest --log-level=DEBUG")


if __name__ == "__main__":

    if len(sys.argv) <= 1 or sys.argv[1] not in ['install', 'test', 'dist']:
        print("usage: binaries.py [install|test|dist]")
        sys.exit(-1)

    env = Environment()

    # Runs the command in sys.argv[1] (install|test|dist)
    getattr(env, sys.argv[1])()
    sys.exit(0)
