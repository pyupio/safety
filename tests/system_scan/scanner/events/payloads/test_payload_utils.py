import pytest
from safety.system_scan.scanner.events.payloads.utils import required


def test_required_raises_type_error_with_correct_message():
    field_name = "test_field"
    required_func = required(field_name)

    with pytest.raises(TypeError, match="Missing required argument: test_field"):
        required_func()


def test_required_creates_callable():
    required_func = required("some_field")
    assert callable(required_func)


def test_required_with_different_field_names():
    machine_id_func = required("machine_id")
    username_func = required("os_username")

    with pytest.raises(TypeError, match="Missing required argument: machine_id"):
        machine_id_func()

    with pytest.raises(TypeError, match="Missing required argument: os_username"):
        username_func()
