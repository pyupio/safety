from collections import defaultdict
from pathlib import Path
import sys
from typing import Generator, List, Optional

from safety_schemas.models import FileType, PythonDependency
from safety_schemas.models.package import PythonSpecification
from ..base import InspectableFile
from dparse import parse, filetypes

from packaging.specifiers import SpecifierSet
from packaging.version import parse as parse_version
from packaging.utils import canonicalize_name


def get_closest_ver(versions, version, spec: SpecifierSet):
    results = {'upper': None, 'lower': None}

    if (not version and not spec) or not versions:
        return results

    sorted_versions = sorted(versions, key=lambda ver: parse_version(ver), reverse=True)

    if not version:
        sorted_versions = spec.filter(sorted_versions, prereleases=False)

        upper = None
        lower = None

        try:
            sorted_versions = list(sorted_versions)
            upper = sorted_versions[0]
            lower = sorted_versions[-1]
            results['upper'] = upper
            results['lower'] = lower if upper != lower else None
        except IndexError:
            pass

        return results

    current_v = parse_version(version)

    for v in sorted_versions:
        index = parse_version(v)

        if index > current_v:
            results['upper'] = index

        if index < current_v:
            results['lower'] = index
            break

    return results


def is_pinned_requirement(spec: SpecifierSet) -> bool:
    if not spec or len(spec) != 1:
        return False

    specifier = next(iter(spec))

    return (specifier.operator == '==' and '*' != specifier.version[-1]) \
        or specifier.operator == '==='


def find_version(requirements):
    ver = None

    if len(requirements) != 1:
        return ver

    specs = requirements[0].specifier

    if is_pinned_requirement(specs):
        ver = next(iter(requirements[0].specifier)).version

    return ver


def is_supported_by_parser(path):
    supported_types = (".txt", ".in", ".yml", ".ini", "Pipfile",
                       "Pipfile.lock", "setup.cfg", "poetry.lock")
    return path.endswith(supported_types)


def parse_requirement(dep, found: Optional[str]) -> PythonSpecification:
    req = PythonSpecification(dep)
    req.found = Path(found).resolve() if found else None

    if req.specifier == SpecifierSet(''):
        req.specifier = SpecifierSet('>=0')

    return req


def read_requirements(fh, resolve=True):
    """
    Reads requirements from a file like object and (optionally) from referenced files.
    :param fh: file like object to read from
    :param resolve: boolean. resolves referenced files.
    :return: generator
    """
    is_temp_file = not hasattr(fh, 'name')
    path = None
    found = Path('temp_file')
    file_type = filetypes.requirements_txt
    absolute_path: Optional[Path] = None

    if not is_temp_file and is_supported_by_parser(fh.name):
        path = fh.name
        absolute_path = Path(path).resolve()
        found = absolute_path
        file_type = None

    content = fh.read()
    dependency_file = parse(content, path=path, resolve=resolve,
                            file_type=file_type)

    reqs_pkg = defaultdict(list)

    for req in dependency_file.resolved_dependencies:
        reqs_pkg[canonicalize_name(req.name)].append(req)

    for pkg, reqs in reqs_pkg.items():
        specifications = list(
            map(lambda req: parse_requirement(req, str(absolute_path)), reqs))
        version = find_version(specifications)

        yield PythonDependency(name=pkg, version=version,
                      specifications=specifications,
                      found=found,
                      absolute_path=absolute_path,
                      insecure_versions=[],
                      secure_versions=[], latest_version=None,
                      latest_version_without_known_vulnerabilities=None,
                      more_info_url=None)


def read_dependencies(fh, resolve=True):
    path = fh.name
    absolute_path = Path(path).resolve()
    found = absolute_path

    content = fh.read()
    dependency_file = parse(content, path=path, resolve=resolve)

    reqs_pkg = defaultdict(list)

    for req in dependency_file.resolved_dependencies:
        reqs_pkg[canonicalize_name(req.name)].append(req)

    for pkg, reqs in reqs_pkg.items():
        specifications = list(
            map(lambda req: parse_requirement(req, str(absolute_path)), reqs))
        version = find_version(specifications)

        yield PythonDependency(name=pkg, version=version,
                      specifications=specifications,
                      found=found,
                      absolute_path=absolute_path,
                      insecure_versions=[],
                      secure_versions=[], latest_version=None,
                      latest_version_without_known_vulnerabilities=None,
                      more_info_url=None)

def read_virtual_environment_dependencies(f: InspectableFile) \
    -> Generator[PythonDependency, None, None]:

    env_path = Path(f.file.name).resolve().parent

    if sys.platform.startswith('win'):
        site_pkgs_path = env_path / Path("Lib/site-packages/")
    else:
        site_pkgs_path = Path('lib/')
        try:
            site_pkgs_path = next((env_path / site_pkgs_path).glob("*/site-packages/"))
        except StopIteration:
            # Unable to find packages for foo env
            return

    if not site_pkgs_path.resolve().exists():
        # Unable to find packages for foo env
        return
    
    dep_paths = site_pkgs_path.glob("*/METADATA")

    for path in dep_paths:
        if not path.is_file():
            continue

        dist_info_folder = path.parent
        dep_name, dep_version = dist_info_folder.name.replace(".dist-info", "").split("-")

        yield PythonDependency(name=dep_name, version=dep_version,
                specifications=[
                    PythonSpecification(f"{dep_name}=={dep_version}", 
                                        found=site_pkgs_path)], 
                found=site_pkgs_path, insecure_versions=[],
                secure_versions=[], latest_version=None, 
                latest_version_without_known_vulnerabilities=None,
                more_info_url=None)


def get_dependencies(f: InspectableFile) -> List[PythonDependency]:
    if not f.file_type:
        return []
    
    if f.file_type in [FileType.REQUIREMENTS_TXT, FileType.POETRY_LOCK, 
                       FileType.PIPENV_LOCK]:
        return list(read_dependencies(f.file, resolve=True))
    
    if f.file_type == FileType.VIRTUAL_ENVIRONMENT:
        return list(read_virtual_environment_dependencies(f))

    return []