# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///

def update_pyproject_toml(file_path: str) -> None:
    """
    Updates the pyproject.toml file by replacing 'type = "container"' with 
    'type = "virtual"'

    This allows to keep using the same hatch test environment configuration for 
    local and CI, local uses container.

    This won't be needed if hatch supports a way to set the type of environment 
    via environment variables. This is a workaround until that is implemented.
    
    Args:
        file_path: Path to the pyproject.toml file
    """
    try:
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace the content
        updated_content = content.replace('type = "container"',
                                          'type = "virtual"')
        
        # Write back to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)

    except Exception as e:
        print(f"Error updating {file_path}: {str(e)}")
        raise

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python update_config.py <path_to_pyproject.toml>")
        sys.exit(1)
        
    update_pyproject_toml(sys.argv[1])