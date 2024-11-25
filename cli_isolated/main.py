from pathlib import Path
from safety_schemas.models import FileType
from read_dependency_files import process_files
from vulnerability_checker import check_vulnerabilities

# Initialize input files
file_path = Path("/Users/dylanpulver/Repos/pyup/safety/test_requirements.txt")
file_type = FileType.REQUIREMENTS_TXT

# String buffer to accumulate results
# output_buffer = []

# Process files and check for vulnerabilities
for path, inspectable_file in process_files([file_path], [file_type]):
    # output_buffer.append(f"Processed file: {path}")
    # file_model, file_output = check_vulnerabilities(path, inspectable_file)
    # output_buffer.append(file_output)

