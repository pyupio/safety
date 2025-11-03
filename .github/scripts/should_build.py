# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
import sys
import argparse
from pathlib import Path
import tomllib


def read_toml_config(file_path: str) -> dict:
    """Read and parse TOML configuration file."""
    with open(file_path, "rb") as f:
        return tomllib.load(f)


def should_build_binary(
    os_type: str | None, python_version: str | None, target: str | None, config: dict
) -> bool:
    """Determine if this combination should trigger a binary build."""
    try:
        artifacts_config = config["tool"]["project"]["build"]["artifacts"]
        return (
            python_version == artifacts_config.get("python")
            and target in artifacts_config.get("targets", [])
            and os_type in artifacts_config.get("os_type", [])
        )
    except KeyError:
        return False


def should_build_package(
    os_type: str | None, python_version: str, rust_target: str | None, config: dict
) -> bool:
    """Determine if this combination should trigger a package build."""
    try:
        artifacts_config = config["tool"]["project"]["build"]["artifacts"]
        return (
            os_type == artifacts_config.get("package_os_type")
            and python_version == artifacts_config.get("python")
            and not rust_target
        )
    except KeyError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Determine if a combination should trigger a binary build"
    )
    parser.add_argument(
        "build_type",
        choices=["binary", "package"],
        help="Type of build to check (binary or package)",
    )
    parser.add_argument("toml_path", help="Path to pyproject.toml file")
    parser.add_argument("--os-type", help="OS type to check")
    parser.add_argument("--python-version", help="Python version to check")
    parser.add_argument("--target", help="Target to check")
    parser.add_argument("--rust-target", help="Rust target to check")

    args = parser.parse_args()

    toml_path = Path(args.toml_path)
    if not toml_path.exists():
        print(f"Error: File {toml_path} not found")
        sys.exit(1)

    try:
        config = read_toml_config(str(toml_path))
        should_build = False

        if args.build_type == "binary":
            should_build = should_build_binary(
                args.os_type, args.python_version, args.target, config
            )
        elif args.build_type == "package":
            should_build = should_build_package(
                args.os_type, args.python_version, args.rust_target, config
            )
        # Print true/false for direct use in GitHub Actions
        print(str(should_build).lower())
    except Exception as e:
        print(f"Error processing TOML file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
