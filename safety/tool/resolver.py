from sys import platform
import subprocess


def get_unwrapped_command(name: str) -> str:
    """
    Find the true executable for a command, skipping wrappers/aliases/.bat files.

    Args:
        command: The command to resolve (e.g. 'pip', 'python')

    Returns:
        Path to the actual executable
    """
    if platform in ["win32"]:
        lookup_term = f"{name}.exe"
        where_result = subprocess.run(
            ["where.exe", lookup_term], capture_output=True, text=True
        )
        if where_result.returncode == 0:
            for path in where_result.stdout.splitlines():
                if not path.lower().endswith(f"{name}.bat"):
                    return path

    return name
