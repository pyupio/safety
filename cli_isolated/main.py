from pathlib import Path
from safety_schemas.models import FileType

from read_dependency_files import read_dependency_files
from vulnerability_checker import check_vulnerabilities
from rich.console import Console

console = Console()

file_path = Path("/Users/dylanpulver/Repos/pyup/safety/test_requirements.txt")
file_type = FileType.REQUIREMENTS_TXT

# Call the function and consume the generator
# Process and check vulnerabilities
for path, inspectable_file in read_dependency_files([file_path], [file_type]):
    console.print(f"Processed file: {path}")
    file_model = check_vulnerabilities(path, inspectable_file, console)
    console.print(f"File Model: {file_model}")
