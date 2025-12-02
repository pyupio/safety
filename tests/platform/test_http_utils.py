from unittest.mock import Mock


from safety.platform.http_utils import extract_detail


def test_extract_detail_valid_json_with_detail():
    # Test valid JSON with detail
    response = Mock()
    response.json.return_value = {"detail": "Error message"}
    detail = extract_detail(response)
    assert detail == "Error message"


def test_extract_detail_valid_json_without_detail():
    # Test valid JSON without detail
    response = Mock()
    response.json.return_value = {"message": "Something else"}
    detail = extract_detail(response)
    assert detail is None


def test_extract_detail_invalid_json():
    # Test invalid JSON
    response = Mock()
    response.json.side_effect = ValueError()
    detail = extract_detail(response)
    assert detail is None


def test_extract_detail_empty_response():
    # Test empty response
    response = Mock()
    response.json.return_value = {}
    detail = extract_detail(response)
    assert detail is None
