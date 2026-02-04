from pathlib import Path
from typing import Iterator
from ...models import Detection, DetectionKind
from ...filesystem import FsRuntime
from .collectors import (
    parse_dist_info_dirname,
    parse_egg_info_dirname,
    extract_metadata_field,
    collect_python_dependency_info,
)


class PythonDependencyDetector:
    """
    Detects Python dependencies.
    """

    DIST_INFO_SUFFIX = ".dist-info"
    EGG_INFO_SUFFIX = ".egg-info"

    def detect_packages(
        self, site_packages_path: Path, env_path: Path, fs: FsRuntime
    ) -> Iterator[Detection]:
        """
        Detect all packages in a site-packages directory.

        Args:
            site_packages_path: Path to the site-packages directory
            env_path: Path to the environment
            fs: Filesystem runtime

        Yields:
            Detection objects for each package
        """
        if not fs.is_dir(site_packages_path):
            return

        try:
            import os

            with os.scandir(site_packages_path) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.endswith(self.DIST_INFO_SUFFIX):
                            yield from self._process_dist_info(
                                Path(entry.path), env_path, site_packages_path, fs
                            )
                        elif entry.name.endswith(self.EGG_INFO_SUFFIX):
                            yield from self._process_egg_info(
                                Path(entry.path), env_path, site_packages_path, fs
                            )
        except (OSError, PermissionError):
            return

    def _process_dist_info(
        self,
        dist_info_path: Path,
        env_path: Path,
        site_packages_path: Path,
        fs: FsRuntime,
    ) -> Iterator[Detection]:
        """
        Process a dist-info directory.

        Args:
            dist_info_path: Path to the dist-info directory
            env_path: Path to the environment
            site_packages_path: Path to the site-packages directory
            fs: Filesystem runtime

        Yields:
            Detection objects for the package
        """
        # Try to parse name and version from directory name first
        name, version = parse_dist_info_dirname(
            dist_info_path.name, self.DIST_INFO_SUFFIX
        )

        # Only read METADATA if we couldn't parse from dirname
        if not name or not version:
            metadata_content = fs.read_text(
                dist_info_path / "METADATA", max_bytes=64_000
            )
            if metadata_content:
                if not name:
                    name = extract_metadata_field(metadata_content, "Name")
                if not version:
                    version = extract_metadata_field(metadata_content, "Version")

        if not name:
            return  # Can't create a package without a name

        # Collect package information as payload object
        dependency_info = collect_python_dependency_info(
            dist_info_path, name, version, fs
        )

        yield Detection(
            kind=DetectionKind.DEPENDENCY,
            subtype="python",
            stable_id=f"pkg:{env_path}:{dist_info_path}",
            primary_path=str(dist_info_path),
            scope="environment",
            found_via=["ENV_SITE_PACKAGES"],
            meta=dependency_info,
        )

    def _process_egg_info(
        self,
        egg_info_path: Path,
        env_path: Path,
        site_packages_path: Path,
        fs: FsRuntime,
    ) -> Iterator[Detection]:
        """
        Process an egg-info directory (legacy format).

        Args:
            egg_info_path: Path to the egg-info directory
            env_path: Path to the environment
            site_packages_path: Path to the site-packages directory
            fs: Filesystem runtime

        Yields:
            Detection objects for the package
        """
        # Parse name and version from directory name
        name, version = parse_egg_info_dirname(egg_info_path.name, self.EGG_INFO_SUFFIX)

        if not name:
            # Try PKG-INFO file
            pkg_info = fs.read_text(egg_info_path / "PKG-INFO", max_bytes=32_000)
            if pkg_info:
                name = extract_metadata_field(pkg_info, "Name")
                version = extract_metadata_field(pkg_info, "Version")

        if not name:
            return

        # Collect package information as payload object
        dependency_info = collect_python_dependency_info(
            egg_info_path, name, version, fs
        )

        yield Detection(
            kind=DetectionKind.DEPENDENCY,
            subtype="python",
            stable_id=f"pkg:{env_path}:{egg_info_path}",
            primary_path=str(egg_info_path),
            scope="environment",
            found_via=["ENV_SITE_PACKAGES"],
            meta=dependency_info,
        )
