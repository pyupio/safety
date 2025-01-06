from importlib.metadata import distributions
import tomli
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

def get_project_dependencies():
    try:
        with open("pyproject.toml", "rb") as f:
            pyproject = tomli.load(f)
            deps = pyproject.get("project", {}).get("dependencies", [])
            return {canonicalize_name(Requirement(dep).name): dep 
                   for dep in deps if isinstance(dep, str)}
    except Exception as e:
        print(f"Error reading dependencies: {e}")
        return {}

def pytest_configure(config):
    main_deps_specs = get_project_dependencies()
    all_dists = {canonicalize_name(dist.metadata['Name']): 
                 (dist.metadata['Name'], dist.version) 
                 for dist in distributions()}
    
    # Main dependencies table
    print(f"\n[{len(main_deps_specs)}] Main Dependencies:")
    print("-" * 60)
    print("%-20s %-25s %-15s" % ("Package", "Specification", "Installed"))
    print("-" * 60)
    
    for pkg_norm, spec in sorted(main_deps_specs.items()):
        if pkg_norm in all_dists:
            name, version = all_dists[pkg_norm]
            print("%-20s %-25s %-15s" % (name, spec, version))
    
    other_pkgs = [f"{name} {ver}" 
                  for pkg_norm, (name, ver) in sorted(all_dists.items()) 
                  if pkg_norm not in main_deps_specs]
    
    # Other dependencies in wrapped format
    print(f"\n[{len(other_pkgs)}] Other Dependencies:")
    print("-" * 80)    
    
    # Print other dependencies with wrapping
    line = ""
    for pkg in other_pkgs:
        if len(line) + len(pkg) + 2 > 78:
            print(line.rstrip(", "))
            line = pkg + ", "
        else:
            line += pkg + ", "
    if line:
        print(line.rstrip(", "))