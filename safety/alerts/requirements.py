from __future__ import unicode_literals

from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet
import requests
from typing import Any, Optional, Generator, Tuple, List

from datetime import datetime
from dparse import parse, parser, updater, filetypes
from dparse.dependencies import Dependency
from dparse.parser import setuptools_parse_requirements_backport as parse_requirements


class RequirementFile(object):
    """
    Class representing a requirements file with its content and metadata.

    Attributes:
        path (str): The file path.
        content (str): The content of the file.
        sha (Optional[str]): The SHA of the file.
    """
    def __init__(self, path: str, content: str, sha: Optional[str] = None):
        self.path = path
        self.content = content
        self.sha = sha
        self._requirements = None
        self._other_files = None
        self._is_valid = None
        self.is_pipfile = False
        self.is_pipfile_lock = False
        self.is_setup_cfg = False

    def __str__(self) -> str:
        return "RequirementFile(path='{path}', sha='{sha}', content='{content}')".format(
            path=self.path,
            content=self.content[:30] + "[truncated]" if len(self.content) > 30 else self.content,
            sha=self.sha
        )

    @property
    def is_valid(self) -> Optional[bool]:
        """
        Checks if the requirements file is valid by parsing it.

        Returns:
            bool: True if the file is valid, False otherwise.
        """
        if self._is_valid is None:
            self._parse()
        return self._is_valid

    @property
    def requirements(self) -> Optional[List]:
        """
        Returns the list of requirements parsed from the file.

        Returns:
            List: The list of requirements.
        """
        if not self._requirements:
            self._parse()
        return self._requirements

    @property
    def other_files(self) -> Optional[List]:
        """
        Returns the list of other files resolved from the requirements file.

        Returns:
            List: The list of other files.
        """
        if not self._other_files:
            self._parse()
        return self._other_files

    @staticmethod
    def parse_index_server(line: str) -> Optional[str]:
        """
        Parses the index server from a given line.

        Args:
            line (str): The line to parse.

        Returns:
            str: The parsed index server.
        """
        return parser.Parser.parse_index_server(line)

    def _hash_parser(self, line: str) -> Optional[Tuple[str, List[str]]]:
        """
        Parses the hashes from a given line.

        Args:
            line (str): The line to parse.

        Returns:
            List: The list of parsed hashes.
        """
        return parser.Parser.parse_hashes(line)

    def _parse_requirements_txt(self) -> None:
        """
        Parses the requirements.txt file format.
        """
        self.parse_dependencies(filetypes.requirements_txt)

    def _parse_conda_yml(self) -> None:
        """
        Parses the conda.yml file format.
        """
        self.parse_dependencies(filetypes.conda_yml)

    def _parse_tox_ini(self) -> None:
        """
        Parses the tox.ini file format.
        """
        self.parse_dependencies(filetypes.tox_ini)

    def _parse_pipfile(self) -> None:
        """
        Parses the Pipfile format.
        """
        self.parse_dependencies(filetypes.pipfile)
        self.is_pipfile = True

    def _parse_pipfile_lock(self) -> None:
        """
        Parses the Pipfile.lock format.
        """
        self.parse_dependencies(filetypes.pipfile_lock)
        self.is_pipfile_lock = True

    def _parse_setup_cfg(self) -> None:
        """
        Parses the setup.cfg format.
        """
        self.parse_dependencies(filetypes.setup_cfg)
        self.is_setup_cfg = True

    def _parse(self) -> None:
        """
        Parses the requirements file to extract dependencies and other files.
        """
        self._requirements, self._other_files = [], []
        if self.path.endswith('.yml') or self.path.endswith(".yaml"):
            self._parse_conda_yml()
        elif self.path.endswith('.ini'):
            self._parse_tox_ini()
        elif self.path.endswith("Pipfile"):
            self._parse_pipfile()
        elif self.path.endswith("Pipfile.lock"):
            self._parse_pipfile_lock()
        elif self.path.endswith('setup.cfg'):
            self._parse_setup_cfg()
        else:
            self._parse_requirements_txt()
        self._is_valid = len(self._requirements) > 0 or len(self._other_files) > 0

    def parse_dependencies(self, file_type: str) -> None:
        """
        Parses the dependencies from the content based on the file type.

        Args:
            file_type (str): The type of the file.
        """
        result = parse(
            self.content,
            path=self.path,
            sha=self.sha,
            file_type=file_type,
            marker=(
                ("pyup: ignore file", "pyup:ignore file"),  # file marker
                ("pyup: ignore", "pyup:ignore"),  # line marker
            )
        )
        for dep in result.dependencies:
            req = Requirement(
                name=dep.name,
                specs=dep.specs,
                line=dep.line,
                lineno=dep.line_numbers[0] if dep.line_numbers else 0,
                extras=dep.extras,
                file_type=file_type,
            )
            req.index_server = dep.index_server
            if self.is_pipfile:
                req.pipfile = self.path
            req.hashes = dep.hashes
            self._requirements.append(req)
        self._other_files = result.resolved_files

    def iter_lines(self, lineno: int = 0) -> Generator[str, None, None]:
        """
        Iterates over lines in the content starting from a specific line number.

        Args:
            lineno (int): The line number to start from.

        Yields:
            str: The next line in the content.
        """
        for line in self.content.splitlines()[lineno:]:
            yield line

    @classmethod
    def resolve_file(cls, file_path: str, line: str) -> str:
        """
        Resolves a file path from a given line.

        Args:
            file_path (str): The file path to resolve.
            line (str): The line containing the file path.

        Returns:
            str: The resolved file path.
        """
        return parser.Parser.resolve_file(file_path, line)


class Requirement(object):
    """
    Class representing a single requirement.

    Attributes:
        name (str): The name of the requirement.
        specs (SpecifierSet): The version specifiers for the requirement.
        line (str): The line containing the requirement.
        lineno (int): The line number of the requirement.
        extras (List): The extras for the requirement.
        file_type (str): The type of the file containing the requirement.
    """
    def __init__(self, name: str, specs: SpecifierSet, line: str, lineno: int, extras: List, file_type: str):
        self.name = name
        self.key = name.lower()
        self.specs = specs
        self.line = line
        self.lineno = lineno
        self.index_server = None
        self.extras = extras
        self.hashes = []
        self.file_type = file_type
        self.pipfile = None

        self.hashCmp = (
            self.key,
            self.specs,
            frozenset(self.extras),
        )

        self._is_insecure = None
        self._changelog = None

        # Convert compatible releases to a range of versions
        if len(self.specs._specs) == 1 and next(iter(self.specs._specs))._spec[0] == "~=":
            # convert compatible releases to something more easily consumed,
            # e.g. '~=1.2.3' is equivalent to '>=1.2.3,<1.3.0', while '~=1.2'
            # is equivalent to '>=1.2,<2.0'
            min_version = next(iter(self.specs._specs))._spec[1]
            max_version = list(parse_version(min_version).release)
            max_version[-1] = 0
            max_version[-2] = max_version[-2] + 1
            max_version = '.'.join(str(x) for x in max_version)

            self.specs = SpecifierSet('>=%s,<%s' % (min_version, max_version))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, Requirement) and
            self.hashCmp == other.hashCmp
        )

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __str__(self) -> str:
        return "Requirement.parse({line}, {lineno})".format(line=self.line, lineno=self.lineno)

    def __repr__(self) -> str:
        return self.__str__()

    @property
    def is_pinned(self) -> bool:
        """
        Checks if the requirement is pinned to a specific version.

        Returns:
            bool: True if pinned, False otherwise.
        """
        if len(self.specs._specs) == 1 and next(iter(self.specs._specs))._spec[0] == "==":
            return True
        return False

    @property
    def is_open_ranged(self) -> bool:
        """
        Checks if the requirement has an open range of versions.

        Returns:
            bool: True if open ranged, False otherwise.
        """
        if len(self.specs._specs) == 1 and next(iter(self.specs._specs))._spec[0] == ">=":
            return True
        return False

    @property
    def is_ranged(self) -> bool:
        """
        Checks if the requirement has a range of versions.

        Returns:
            bool: True if ranged, False otherwise.
        """
        return len(self.specs._specs) >= 1 and not self.is_pinned

    @property
    def is_loose(self) -> bool:
        """
        Checks if the requirement has no version specifiers.

        Returns:
            bool: True if loose, False otherwise.
        """
        return len(self.specs._specs) == 0

    @staticmethod
    def convert_semver(version: str) -> dict:
        """
        Converts a version string to a semantic version dictionary.

        Args:
            version (str): The version string.

        Returns:
            dict: The semantic version dictionary.
        """
        semver = {'major': 0, "minor": 0, "patch": 0}
        version = version.split(".")
        # don't be overly clever here. repitition makes it more readable and works exactly how
        # it is supposed to
        try:
            semver['major'] = int(version[0])
            semver['minor'] = int(version[1])
            semver['patch'] = int(version[2])
        except (IndexError, ValueError):
            pass
        return semver

    @property
    def can_update_semver(self) -> bool:
        """
        Checks if the requirement can be updated based on semantic versioning rules.

        Returns:
            bool: True if it can be updated, False otherwise.
        """
        # return early if there's no update filter set
        if "pyup: update" not in self.line:
            return True
        update = self.line.split("pyup: update")[1].strip().split("#")[0]
        current_version = Requirement.convert_semver(next(iter(self.specs._specs))._spec[1])
        next_version = Requirement.convert_semver(self.latest_version)
        if update == "major":
            if current_version['major'] < next_version['major']:
                return True
        elif update == 'minor':
            if current_version['major'] < next_version['major'] \
                    or current_version['minor'] < next_version['minor']:
                return True
        return False

    @property
    def filter(self):
        """
        Returns the filter for the requirement if specified.

        Returns:
            Optional[SpecifierSet]: The filter specifier set, or None if not specified.
        """
        rqfilter = False
        if "rq.filter:" in self.line:
            rqfilter = self.line.split("rq.filter:")[1].strip().split("#")[0]
        elif "pyup:" in self.line:
            if "pyup: update" not in self.line:
                rqfilter = self.line.split("pyup:")[1].strip().split("#")[0]
                # unset the filter once the date set in 'until' is reached
                if "until" in rqfilter:
                    rqfilter, until = [l.strip() for l in rqfilter.split("until")]
                    try:
                        until = datetime.strptime(until, "%Y-%m-%d")
                        if until < datetime.now():
                            rqfilter = False
                    except ValueError:
                        # wrong date formatting
                        pass
        if rqfilter:
            try:
                rqfilter, = parse_requirements("filter " + rqfilter)
                if len(rqfilter.specifier._specs) > 0:
                    return rqfilter.specifier
            except ValueError:
                pass
        return False

    @property
    def version(self) -> Optional[str]:
        """
        Returns the current version of the requirement.

        Returns:
            Optional[str]: The current version, or None if not pinned.
        """
        if self.is_pinned:
            return next(iter(self.specs._specs))._spec[1]

        specs = self.specs
        if self.filter:
            specs = SpecifierSet(
                ",".join(["".join(s._spec) for s in list(specs._specs) + list(self.filter._specs)])
            )
        return self.get_latest_version_within_specs(
            specs,
            versions=self.package.versions,
            prereleases=self.prereleases
        )

    def get_hashes(self, version: str) -> List:
        """
        Retrieves the hashes for a specific version from PyPI.

        Args:
            version (str): The version to retrieve hashes for.

        Returns:
            List: A list of hashes for the specified version.
        """
        r = requests.get('https://pypi.org/pypi/{name}/{version}/json'.format(
            name=self.key,
            version=version
        ))
        hashes = []
        data = r.json()

        for item in data.get("urls", {}):
            sha256 = item.get("digests", {}).get("sha256", False)
            if sha256:
                hashes.append({"hash": sha256, "method": "sha256"})
        return hashes

    def update_version(self, content: str, version: str, update_hashes: bool = True) -> str:
        """
        Updates the version of the requirement in the content.

        Args:
            content (str): The original content.
            version (str): The new version to update to.
            update_hashes (bool): Whether to update the hashes as well.

        Returns:
            str: The updated content.
        """
        if self.file_type == filetypes.tox_ini:
            updater_class = updater.ToxINIUpdater
        elif self.file_type == filetypes.conda_yml:
            updater_class = updater.CondaYMLUpdater
        elif self.file_type == filetypes.requirements_txt:
            updater_class = updater.RequirementsTXTUpdater
        elif self.file_type == filetypes.pipfile:
            updater_class = updater.PipfileUpdater
        elif self.file_type == filetypes.pipfile_lock:
            updater_class = updater.PipfileLockUpdater
        elif self.file_type == filetypes.setup_cfg:
            updater_class = updater.SetupCFGUpdater
        else:
            raise NotImplementedError

        dep = Dependency(
            name=self.name,
            specs=self.specs,
            line=self.line,
            line_numbers=[self.lineno, ] if self.lineno != 0 else None,
            dependency_type=self.file_type,
            hashes=self.hashes,
            extras=self.extras
        )
        hashes = []
        if self.hashes and update_hashes:
            hashes = self.get_hashes(version)

        return updater_class.update(
            content=content,
            dependency=dep,
            version=version,
            hashes=hashes,
            spec="=="
        )

    @classmethod
    def parse(cls, s: str, lineno: int, file_type: str = filetypes.requirements_txt) -> 'Requirement':
        """
        Parses a requirement from a line of text.

        Args:
            s (str): The line of text.
            lineno (int): The line number.
            file_type (str): The type of the file containing the requirement.

        Returns:
            Requirement: The parsed requirement.
        """
        # setuptools requires a space before the comment. If this isn't the case, add it.
        if "\t#" in s:
            parsed, = parse_requirements(s.replace("\t#", "\t #"))
        else:
            parsed, = parse_requirements(s)

        return cls(
            name=parsed.name,
            specs=parsed.specifier,
            line=s,
            lineno=lineno,
            extras=parsed.extras,
            file_type=file_type
        )
