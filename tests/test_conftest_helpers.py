from types import SimpleNamespace

from tests import conftest


def test_installed_distributions_skip_missing_names(monkeypatch):
    monkeypatch.setattr(
        conftest,
        "distributions",
        lambda: [
            SimpleNamespace(metadata={"Name": "Example_Package"}, version="1.0"),
            SimpleNamespace(metadata={}, version="2.0"),
        ],
    )

    assert conftest.get_installed_distributions() == {
        "example-package": ("Example_Package", "1.0")
    }
