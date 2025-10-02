"""
Test that project dependencies have appropriate version constraints.

This test verifies that dependencies are not overly restrictive,
allowing for better compatibility with downstream projects.
"""
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
import pytest


def get_pyproject_dependencies():
    """Read dependencies from pyproject.toml."""
    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)
    return pyproject.get("project", {}).get("dependencies", [])


def test_filelock_dependency_not_overly_restrictive():
    """
    Test that filelock dependency allows versions >= 3.16.1 without tight upper bounds.

    Issue #665: filelock should use >= instead of ~= to avoid conflicts
    with other packages that need newer versions.
    """
    dependencies = get_pyproject_dependencies()

    # Find filelock dependency
    filelock_dep = None
    for dep in dependencies:
        req = Requirement(dep)
        if req.name.lower() == "filelock":
            filelock_dep = dep
            break

    assert filelock_dep is not None, "filelock dependency not found"

    req = Requirement(filelock_dep)
    specifier = req.specifier

    # Check that it has a lower bound of >= 3.16.1
    assert any(
        spec.operator == ">=" and spec.version == "3.16.1"
        for spec in specifier
    ), f"filelock should have >=3.16.1 lower bound, got: {filelock_dep}"

    # Check that it does NOT have a restrictive upper bound like <4.0
    # We want to allow filelock 4.x and higher
    has_restrictive_upper_bound = any(
        spec.operator in ("<", "<=") and spec.version.startswith(("3.", "4."))
        for spec in specifier
    )

    assert not has_restrictive_upper_bound, (
        f"filelock should not have restrictive upper bound (<4.0 or similar). "
        f"Got: {filelock_dep}. This prevents compatibility with projects needing newer versions."
    )


def test_psutil_dependency_not_overly_restrictive():
    """
    Test that psutil dependency allows versions >= 6.1.0 without tight upper bounds.

    Issue #665: psutil should use >= instead of ~= to avoid conflicts
    and allow newer major versions like 7.x.
    """
    dependencies = get_pyproject_dependencies()

    # Find psutil dependency
    psutil_dep = None
    for dep in dependencies:
        req = Requirement(dep)
        if req.name.lower() == "psutil":
            psutil_dep = dep
            break

    assert psutil_dep is not None, "psutil dependency not found"

    req = Requirement(psutil_dep)
    specifier = req.specifier

    # Check that it has a lower bound of >= 6.1.0
    assert any(
        spec.operator == ">=" and spec.version == "6.1.0"
        for spec in specifier
    ), f"psutil should have >=6.1.0 lower bound, got: {psutil_dep}"

    # Check that it does NOT have a restrictive upper bound like <8.0
    # We want to allow psutil 7.x, 8.x and higher
    has_restrictive_upper_bound = any(
        spec.operator in ("<", "<=") and spec.version.startswith(("6.", "7.", "8."))
        for spec in specifier
    )

    assert not has_restrictive_upper_bound, (
        f"psutil should not have restrictive upper bound (<8.0 or similar). "
        f"Got: {psutil_dep}. This prevents compatibility with projects needing newer versions like 7.0."
    )


def test_dependencies_can_be_parsed():
    """Sanity test that all dependencies can be parsed as valid requirements."""
    dependencies = get_pyproject_dependencies()

    assert len(dependencies) > 0, "No dependencies found in pyproject.toml"

    for dep in dependencies:
        try:
            req = Requirement(dep)
            assert req.name, f"Dependency has no name: {dep}"
        except Exception as e:
            pytest.fail(f"Failed to parse dependency '{dep}': {e}")
