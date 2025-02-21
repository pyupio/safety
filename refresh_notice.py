#!/usr/bin/env python3
import importlib.metadata
from pathlib import Path
from typing import List, Tuple

def normalize_package_name(name: str) -> str:
    """Normalize package name to lowercase with hyphens."""
    return name.lower().replace('_', '-').replace('.', '-')

def get_license_from_classifier(classifiers: List[str]) -> str:
    """Extract license from classifier if available."""
    for c in classifiers:
        if 'License :: OSI Approved ::' in c:
            return c.split('License :: OSI Approved :: ')[-1]
    return ''

def get_license(dist) -> str:
    """Get license information from package metadata."""
    classifiers = dist.metadata.get_all('Classifier') or []
    classifier_license = get_license_from_classifier(classifiers)
    
    # Get direct license field
    license = dist.metadata.get('License', '')
    
    # If license is too long (probably full license text) and we have a classifier, use classifier
    if len(license) > 100 and classifier_license:
        return classifier_license
    
    # Try License field first
    if license:
        return license
    
    # Try License-Expression
    if dist.metadata.get('License-Expression'):
        return dist.metadata['License-Expression']
    
    # Use classifier license if available
    if classifier_license:
        return classifier_license
            
    return 'License not found'

def get_all_packages() -> List[Tuple[str, str, str]]:
    """Get all packages with their versions and licenses."""
    packages = [
        (normalize_package_name(dist.metadata['Name']), 
         dist.version, 
         get_license(dist))
        for dist in importlib.metadata.distributions()
    ]
    return sorted(packages)

def generate_markdown_table(packages: List[Tuple[str, str, str]], output_file: str):
    """Generate markdown table and save to file."""
    with open(output_file, 'w') as f:
        # Write header
        f.write('# Package Licenses\n\n')
        f.write('| Name | Version | License |\n')
        f.write('|------|---------|----------|\n')
        
        # Write package rows
        for name, version, license in packages:
            # Escape any pipe characters in the license
            license = license.replace('|', '\\|')
            f.write(f'| {name} | {version} | {license} |\n')

def main():
    packages = get_all_packages()
    generate_markdown_table(packages, 'LICENSES/NOTICE.md')
    print(f"Generated package_licenses.md with {len(packages)} packages")

if __name__ == '__main__':
    main()
