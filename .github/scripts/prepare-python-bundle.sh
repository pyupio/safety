#!/bin/bash
# Create compressed Python distribution bundle for PyApp
# Usage: prepare-python-bundle.sh <python-dist-dir> <output-bundle-path>
# Works in: Host OS, Docker containers

set -euo pipefail

PYTHON_DIST="$1"
OUTPUT_BUNDLE="$2"

echo "Creating Python bundle from: $PYTHON_DIST"
echo "Output bundle: $OUTPUT_BUNDLE"

# Verify input directory exists
if [[ ! -d "$PYTHON_DIST" ]]; then
    echo "Error: Python distribution directory not found: $PYTHON_DIST" >&2
    exit 1
fi

# Remove pip executables if they exist
echo "Looking for pip executables..."

FOUND_PIP=false
for bindir in "bin" "Scripts"; do
    if [[ -d "$PYTHON_DIST/$bindir" ]] && ls "$PYTHON_DIST/$bindir"/pip* 2>/dev/null | grep -q .; then

        ls "$PYTHON_DIST/$bindir"/pip*
        rm -f "$PYTHON_DIST/$bindir/pip"* 2>/dev/null || true
        rm -f "$PYTHON_DIST/$bindir/easy_install"* 2>/dev/null || true
        echo "✅ Removed pip executables from $bindir/"
        ls "$PYTHON_DIST/$bindir"
        FOUND_PIP=true
    fi
done

if [[ "$FOUND_PIP" == "false" ]]; then
    echo "ℹ️  No pip executables found - distribution may not include them"
fi

# Get absolute path of output bundle
OUTPUT_DIR=$(cd "$(dirname "$OUTPUT_BUNDLE")" && pwd)
OUTPUT_BUNDLE="$OUTPUT_DIR/$(basename "$OUTPUT_BUNDLE")"
OUTPUT_DIR=$(dirname "$OUTPUT_BUNDLE")
BUNDLE_NAME=$(basename "$OUTPUT_BUNDLE")

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Change to the Python distribution directory
cd "$PYTHON_DIST"

# Create compressed bundle based on file extension
if [[ "$BUNDLE_NAME" == *.zip ]]; then
    echo "Creating ZIP bundle..."
    
    # Check if we're on Windows (Git Bash or similar)
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ -n "$WINDIR" ]]; then
        echo "Detected Windows environment, using PowerShell for compression..."
        
        # Convert paths to Windows format for PowerShell
        WIN_SOURCE=$(cygpath -w "$(pwd)" 2>/dev/null || pwd)
        WIN_OUTPUT=$(cygpath -w "$OUTPUT_BUNDLE" 2>/dev/null || echo "$OUTPUT_BUNDLE")
        
        # Use PowerShell to create the ZIP file
        powershell.exe -NoProfile -Command "
            \$ErrorActionPreference = 'Stop'
            try {
                # Remove existing file if it exists
                if (Test-Path '$WIN_OUTPUT') {
                    Remove-Item '$WIN_OUTPUT' -Force
                }
                
                # Create the ZIP file
                Compress-Archive -Path '$WIN_SOURCE\*' -DestinationPath '$WIN_OUTPUT' -Force
                
                Write-Host 'ZIP file created successfully'
            } catch {
                Write-Error \"Failed to create ZIP: \$_\"
                exit 1
            }
        "
        
        if [[ $? -ne 0 ]]; then
            echo "Error: Failed to create ZIP using PowerShell" >&2
            exit 1
        fi
    else
        # On Linux/macOS, use the zip command
        if ! command -v zip &> /dev/null; then
            echo "Error: zip command not found" >&2
            exit 1
        fi
        
        zip -r "$OUTPUT_BUNDLE" .
    fi
    
elif [[ "$BUNDLE_NAME" == *.tar.gz ]] || [[ "$BUNDLE_NAME" == *.tgz ]]; then
    echo "Creating tar.gz bundle..."
    
    tar czf "$OUTPUT_BUNDLE" .
    
else
    # Default to tar.gz
    echo "Unknown extension, defaulting to tar.gz..."
    tar czf "${OUTPUT_BUNDLE}.tar.gz" .
    OUTPUT_BUNDLE="${OUTPUT_BUNDLE}.tar.gz"
fi

# Verify bundle was created
if [[ ! -f "$OUTPUT_BUNDLE" ]]; then
    echo "Error: Failed to create bundle: $OUTPUT_BUNDLE" >&2
    exit 1
fi

# Get bundle size for reporting
BUNDLE_SIZE=$(ls -lh "$OUTPUT_BUNDLE" | awk '{print $5}')

echo "Bundle created successfully:"
echo "  Path: $OUTPUT_BUNDLE"
echo "  Size: $BUNDLE_SIZE"

# Output the final bundle path for use in workflows
echo "BUNDLE_PATH=$OUTPUT_BUNDLE"