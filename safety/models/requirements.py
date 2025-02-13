from packaging.specifiers import SpecifierSet


def is_pinned_requirement(spec: SpecifierSet) -> bool:
    """
    Check if a requirement is pinned.

    Args:
        spec (SpecifierSet): The specifier set of the requirement.

    Returns:
        bool: True if the requirement is pinned, False otherwise.
    """
    if not spec or len(spec) != 1:
        return False

    specifier = next(iter(spec))

    return (specifier.operator == '==' and '*' != specifier.version[-1]) or specifier.operator == '==='
