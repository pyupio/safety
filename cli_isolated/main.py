from pathlib import Path
from safety_schemas.models import FileType

from read_dependency_files import read_dependency_files


file_path = Path("/Users/dylanpulver/Repos/pyup/safety/test_requirements.txt")
file_type = FileType.REQUIREMENTS_TXT

# Call the function and consume the generator
for path, inspectable_file in read_dependency_files([file_path], [file_type]):
    print(f"Processed file: {path}")
    print(f"Inspectable File: {inspectable_file}")
