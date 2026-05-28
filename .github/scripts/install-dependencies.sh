#!/bin/bash
# Install dependencies in a Python standalone distribution using uv
# Usage: install-dependencies.sh <python-dist-dir> <source-dir>
# Works in: Host OS, Docker containers (installs uv if needed)

set -euo pipefail

PYTHON_DIST="$1"
SOURCE_DIR="$2"

echo "Installing dependencies in Python distribution: $PYTHON_DIST"
echo "Source directory: $SOURCE_DIR"

# Check if uv is available, install if not
if ! command -v uv &> /dev/null; then
    echo "uv not found, installing..."
    
    # Install uv
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Source the environment to make uv available
    if [[ -f ~/.cargo/env ]]; then
        source ~/.cargo/env
    fi
    
    # Add to PATH for current session
    if [[ -d ~/.cargo/bin ]]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    
    # Verify uv is now available
    if ! command -v uv &> /dev/null; then
        echo "Error: Failed to install uv" >&2
        exit 1
    fi
    
    echo "uv successfully installed"
else
    echo "uv is already available"
fi

# Find Python executable in the distribution
echo "Finding Python executable in: $PYTHON_DIST"

if [[ ! -d "$PYTHON_DIST" ]]; then
    echo "Error: Python distribution directory not found: $PYTHON_DIST" >&2
    exit 1
fi

PYTHON_ROOT="$PYTHON_DIST/python"

if [[ -z "$PYTHON_ROOT" ]]; then
    echo "Error: Could not find Python directory in: $PYTHON_DIST" >&2
    exit 1
fi

echo "Found Python root: $PYTHON_ROOT"

# Determine Python executable path based on platform
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ "$(uname)" == MINGW* ]]; then
    # Windows (including Git Bash)
    PYTHON_EXEC="$PYTHON_ROOT/python.exe"
else
    # Unix-like (Linux, macOS, Docker)
    PYTHON_EXEC="$PYTHON_ROOT/bin/python3.14"
fi

echo "Python executable: $PYTHON_EXEC"
echo "Available files:" >&2
ls -la "$PYTHON_ROOT" >&2
# Only list bin directory if it exists (Unix-like systems)
if [[ -d "$PYTHON_ROOT/bin" ]]; then
    ls -la "$PYTHON_ROOT/bin" >&2
fi

# Verify Python executable exists
if [[ ! -f "$PYTHON_EXEC" ]]; then
    echo "Error: Python executable not found at: $PYTHON_EXEC" >&2
    echo "Available files in $PYTHON_ROOT:" >&2
    ls -la "$PYTHON_ROOT" >&2
    exit 1
fi

# Verify source directory exists
if [[ ! -d "$SOURCE_DIR" ]] && [[ ! -f "$SOURCE_DIR" ]]; then
    echo "Error: Source directory/file not found: $SOURCE_DIR" >&2
    exit 1
fi

# Install dependencies using uv
echo "Installing Safety and dependencies..."
echo "Command: uv pip install --python \"$PYTHON_EXEC\" \"$SOURCE_DIR\""

if uv pip install --python "$PYTHON_EXEC" "$SOURCE_DIR" --system; then
    echo "Dependencies installed successfully"
else
    echo "Error: Failed to install dependencies" >&2
    exit 1
fi

# Cleanup __pycache__ to reduce size
echo "Cleaning up __pycache__ directories..."
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ "$(uname)" == MINGW* ]]; then
    # Windows
    find "$PYTHON_ROOT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
else
    # Unix-like
    find "$PYTHON_ROOT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
fi

echo "Installation completed successfully"