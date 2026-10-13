"""Regression tests for incomplete installed distribution metadata."""
from types import SimpleNamespace

from tests import conftest as local_conftest


def test_get_installed_distributions_skips_missing_and_blank_names(monkeypatch):
    fake = [
        SimpleNamespace(metadata={"Name": "Valid_Pkg"}, version="1.2.3"),
        SimpleNamespace(metadata={}, version="0.1"),
        SimpleNamespace(metadata={"Name": ""}, version="0.1"),
        SimpleNamespace(metadata={"Name": None}, version="0.1"),
        SimpleNamespace(metadata={"Name": 9}, version="0.1"),
    ]
    monkeypatch.setattr(local_conftest, "distributions", lambda: iter(fake))
    assert local_conftest.get_installed_distributions() == {
        "valid-pkg": ("Valid_Pkg", "1.2.3")
    }
