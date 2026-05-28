#!/bin/bash
set -e

BINARY_PATH="$1"
VERSION="$2"

echo "========================================"
echo "Binary Smoke Tests"
echo "========================================"
echo "Binary: $BINARY_PATH"
echo ""

# Verify binary exists
if [ ! -f "$BINARY_PATH" ]; then
  echo "❌ ERROR: Binary not found at $BINARY_PATH"
  exit 1
fi

# Make executable on Unix
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
  chmod +x "$BINARY_PATH"
fi

echo "Setting up Safety config for CI testing..."
SAFETY_CONFIG_DIR="$HOME/.safety"
SAFETY_CONFIG_FILE="$SAFETY_CONFIG_DIR/config.ini"

mkdir -p "$SAFETY_CONFIG_DIR"

cat > "$SAFETY_CONFIG_FILE" << 'EOF'
[settings]
firewall = True
platform = True
events = True
EOF

echo "✓ Created Safety config at $SAFETY_CONFIG_FILE"

# Test 1: Version
echo "Test 1: Version check"
"$BINARY_PATH" --version || exit 1
echo "✓ Version works"

# Test 2: Help
echo ""
echo "Test 2: Help command"
"$BINARY_PATH" --help > /dev/null || exit 1
echo "✓ Help works"

# Test command availability checks
test_commands() {
  local title="$1"
  local help_flag="$2"
  shift 2
  local cmds=("$@")

  echo ""
  echo "$title"
  for cmd in "${cmds[@]}"; do
    if "$BINARY_PATH" "$cmd" "$help_flag" > /dev/null 2>&1; then
      echo "  ✓ $cmd"
    else
      echo "  ✗ $cmd FAILED"
      exit 1
    fi
  done
}

# Test firewall commands - handle case where package managers may not be installed
test_firewall_commands() {
  local title="$1"
  local help_flag="$2"
  shift 2
  local cmds=("$@")

  echo ""
  echo "$title"
  for cmd in "${cmds[@]}"; do
    set +e
    output=$("$BINARY_PATH" "$cmd" "$help_flag" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
      echo "  ✓ $cmd (package manager found)"
    elif echo "$output" | grep -q "Tool $cmd is not installed"; then
      echo "  ⚠ $cmd (package manager not installed - expected behavior)"
    else
      echo "  ✗ $cmd FAILED with unexpected error"
      echo "    Output: $output"
      exit 1
    fi
  done
}

test_commands "Test 3: Commands available" "--help" \
  check scan validate auth configure

test_firewall_commands "Test 4: Firewall commands available" "--safety-help" \
  pip poetry uv npm

# Test 5: Auth subcommands
echo ""
echo "Test 5: Auth subcommands"
for subcmd in "login" "logout" "status"; do
  "$BINARY_PATH" auth "$subcmd" --help > /dev/null 2>&1 && echo "  ✓ auth $subcmd"
done

echo ""
echo "========================================"
echo "✅ All smoke tests passed!"
echo "========================================"

# Clean up the config file (optional - comment out if you want to keep it)
if [ -f "$SAFETY_CONFIG_FILE" ]; then
  rm "$SAFETY_CONFIG_FILE"
  echo "✓ Cleaned up Safety config"
fi