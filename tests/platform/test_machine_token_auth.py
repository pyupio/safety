import base64

import httpx
import pytest

from safety.platform.client import MachineTokenAuth


@pytest.mark.unit
class TestMachineTokenAuth:
    @pytest.mark.parametrize(
        "machine_id,machine_token",
        [
            ("machine-id-123", "token-abc"),
            ("550e8400-e29b-41d4-a716-446655440000", "some-token-value"),
            ("a1b2c3d4e5f6", "hex-token-789"),
        ],
        ids=["basic", "uuid", "hex"],
    )
    def test_basic_auth_encoding_correctness(self, machine_id, machine_token):
        auth = MachineTokenAuth(machine_id, machine_token)
        request = httpx.Request("GET", "https://example.com")
        flow = auth.auth_flow(request)
        modified_request = next(flow)

        assert modified_request.headers["Authorization"].startswith("Basic ")
        encoded_part = modified_request.headers["Authorization"].split("Basic ")[1]
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == f"{machine_id}:{machine_token}"

    def test_colon_in_machine_id(self):
        machine_id = "machine:with:colons"
        machine_token = "token-value"
        auth = MachineTokenAuth(machine_id, machine_token)
        request = httpx.Request("GET", "https://example.com")
        flow = auth.auth_flow(request)
        modified_request = next(flow)

        encoded_part = modified_request.headers["Authorization"].split("Basic ")[1]
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == f"{machine_id}:{machine_token}"
