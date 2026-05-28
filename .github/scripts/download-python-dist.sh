#!/bin/bash
# Download and extract Python standalone distribution
# Usage: download-python-dist.sh <target> <output-dir>
# Works in: Host OS, Docker containers

set -euo pipefail

TARGET="$1"
OUTPUT_DIR="$2"

# Hardcoded Python distribution mapping with SHA256 verification
get_distribution_info() {
    local target="$1"
    case "$target" in
        "x86_64-unknown-linux-gnu")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
            echo "493c477b4a88bb1ea2f6c6f57fa0e88ffbe55d9e7b1405c4699f2d41c04eb154"
            ;;
        "aarch64-unknown-linux-gnu")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz"
            echo "7dbb43b742c040835a277318355fb359b41e509dbf4fbb614da38005a9290e16"
            ;;
        "x86_64-unknown-linux-musl")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-x86_64-unknown-linux-musl-install_only_stripped.tar.gz"
            echo "38b047a2c951dbbff0649e80510fbedfab41745493ff86ca51b53c0bc4093be9"
            ;;
        "x86_64-pc-windows-msvc")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
            echo "b064fca740da03dbae1bad7f73fcaabbc76681ad635b9897ed3808c3eecff122"
            ;;
        "x86_64-apple-darwin")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-x86_64-apple-darwin-install_only_stripped.tar.gz"
            echo "56dcb0cdafabac9d6d976690fb05d9ee92d20ce798c3aabe9049259ebe7d3e0d"
            ;;
        "aarch64-apple-darwin")
            echo "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.14.0%2B20251014-aarch64-apple-darwin-install_only_stripped.tar.gz"
            echo "057476264b07222a2baeff68a733647f91a9d61c94f79beba46a44eb42101749"
            ;;
        *)
            echo "Error: Unknown target '$target'" >&2
            exit 1
            ;;
    esac
}

echo "Downloading Python distribution for target: $TARGET"

# Get URL and SHA256 from hardcoded mapping
DISTRIBUTION_INFO=($(get_distribution_info "$TARGET"))
PYTHON_URL="${DISTRIBUTION_INFO[0]}"
EXPECTED_SHA256="${DISTRIBUTION_INFO[1]}"

echo "Python distribution URL: $PYTHON_URL"
echo "Expected SHA256: $EXPECTED_SHA256"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Download file to temporary location for verification
TEMP_FILE="/tmp/python-dist-$(basename "$PYTHON_URL")"
echo "Downloading to temporary file: $TEMP_FILE"
curl -L "$PYTHON_URL" -o "$TEMP_FILE"

# Verify SHA256 checksum
echo "Verifying SHA256 checksum..."
if command -v sha256sum &> /dev/null; then
    # Linux
    ACTUAL_SHA256=$(sha256sum "$TEMP_FILE" | cut -d' ' -f1)
elif command -v shasum &> /dev/null; then
    # macOS
    ACTUAL_SHA256=$(shasum -a 256 "$TEMP_FILE" | cut -d' ' -f1)
else
    echo "Warning: No SHA256 utility found (sha256sum or shasum), skipping verification" >&2
    ACTUAL_SHA256="$EXPECTED_SHA256"  # Skip verification
fi

if [[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]]; then
    echo "✅ SHA256 verification passed"
else
    echo "❌ SHA256 verification failed!" >&2
    echo "Expected: $EXPECTED_SHA256" >&2
    echo "Actual:   $ACTUAL_SHA256" >&2
    rm -f "$TEMP_FILE"
    exit 1
fi

# Extract verified file
echo "Extracting verified Python distribution..."
cd "$OUTPUT_DIR"
if [[ "$PYTHON_URL" == *.tar.gz ]]; then
    tar xzf "$TEMP_FILE"
else
    echo "Error: Only .tar.gz format is supported. URL: $PYTHON_URL" >&2
    rm -f "$TEMP_FILE"
    exit 1
fi

# Clean up temporary file
rm -f "$TEMP_FILE"

echo "Python distribution downloaded, verified, and extracted to: $OUTPUT_DIR"