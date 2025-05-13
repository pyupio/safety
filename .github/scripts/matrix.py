# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
import json
import sys
import argparse
from pathlib import Path
import tomllib


def read_toml_config(file_path: str) -> dict:
    """Read and parse TOML configuration file."""
    with open(file_path, "rb") as f:
        return tomllib.load(f)


def generate_github_matrix(
    config: dict, include_os_matrix: bool = True, only_os_matrix: bool = False
) -> dict:
    """Generate GitHub Actions matrix configuration from Hatch config.

    Args:
        config: The parsed TOML configuration
        include_os_matrix: Whether to include the OS-specific matrix section
    """
    test_config = config["tool"]["hatch"]["envs"]["test"]
    matrix_configs = test_config["matrix"]

    experimental_targets = ["pydantic-2_10", "pydantic-latest", "click-main-branch"]
    experimental_versions = []

    def is_experimental(python_version, target) -> bool:
        return target in experimental_targets or python_version in experimental_versions

    combinations = []

    if not only_os_matrix:
        # First matrix: all Python versions with no target
        for python_version in matrix_configs[0]["python"]:
            combinations.append(
                {
                    "python-version": python_version,
                    "target": None,
                    "os_type": None,
                    "experimental": is_experimental(python_version, None),
                }
            )

        # Second matrix: specific Python versions with targets
        for python_version in matrix_configs[1]["python"]:
            for target in matrix_configs[1]["targets"]:
                combinations.append(
                    {
                        "python-version": python_version,
                        "target": target,
                        "os_type": None,
                        "experimental": is_experimental(python_version, target),
                    }
                )

    # Third matrix: specific Python versions with os versions
    if only_os_matrix or include_os_matrix:
        for python_version in matrix_configs[2]["python"]:
            for target in matrix_configs[2]["targets"]:
                for os_type in matrix_configs[2]["os_type"]:
                    combinations.append(
                        {
                            "python-version": python_version,
                            "target": target,
                            "os_type": os_type,
                            "experimental": is_experimental(python_version, target),
                        }
                    )

    return {"include": combinations}


def main():
    parser = argparse.ArgumentParser(
        description="Generate GitHub Actions matrix configuration"
    )
    parser.add_argument("toml_path", help="Path to pyproject.toml file")
    parser.add_argument(
        "--no-os-matrix",
        action="store_true",
        help="Exclude the OS-specific matrix section",
    )
    parser.add_argument(
        "--only-os-matrix",
        action="store_true",
        help="Include only the OS-specific matrix section",
    )

    args = parser.parse_args()

    toml_path = Path(args.toml_path)
    if not toml_path.exists():
        print(f"Error: File {toml_path} not found")
        sys.exit(1)

    try:
        config = read_toml_config(str(toml_path))
        matrix = generate_github_matrix(
            config,
            include_os_matrix=not args.no_os_matrix,
            only_os_matrix=args.only_os_matrix,
        )
        # Output single-line JSON for GitHub Actions compatibility
        print(json.dumps(matrix, separators=(",", ":")))
    except Exception as e:
        print(f"Error processing TOML file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
