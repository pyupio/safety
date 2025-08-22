import importlib.metadata as md
import json
import os


def get_package_location(dist):
    """
    Get the installation location of a package distribution.
    """
    try:
        if hasattr(dist, "locate_file") and callable(dist.locate_file):
            root = dist.locate_file("")
            if root:
                return os.path.abspath(str(root))
    except (AttributeError, OSError, TypeError):
        pass

    return ""


def main() -> int:
    """
    List all installed packages with their versions and locations.
    """
    packages = []
    for dist in md.distributions():
        packages.append(
            {
                "name": dist.metadata.get("Name", ""),
                "version": dist.version,
                "location": get_package_location(dist),
            }
        )

    print(json.dumps(packages, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
