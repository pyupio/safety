import subprocess

import pytest


def test_debug_flag():
    result = subprocess.run(['safety', '--debug', 'scan'], capture_output=True, text=True)
    assert "safety.auth" in result.stderr or "DEBUG" in result.stderr

def test_debug_flag_with_value_1():
    result = subprocess.run(['safety', '--debug', '1', 'scan'], capture_output=True, text=True)
    assert "safety.auth" in result.stderr or "DEBUG" in result.stderr

def test_debug_flag_with_value_true():
    result = subprocess.run(['safety', '--debug', 'true', 'scan'], capture_output=True, text=True)
    assert "safety.auth" in result.stderr or "DEBUG" in result.stderr

if __name__ == '__main__':
    pytest.main()
