from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from safety.auth.constants import CLI_AUTH, CLI_AUTH_LOGOUT, CLI_CALLBACK

from safety.auth import main
from safety.auth.main import get_authorization_data, \
    get_logout_url, get_organization, get_redirect_url



class TestAuthMain(unittest.TestCase):

    def setUp(self):
        self.assets = Path(__file__).parent / Path("test_assets/")

    def tearDown(self):
        pass

    def test_get_authorization_data(self):
        org_id = "org_id3dasdasd"
        client = Mock()
        code_verifier = "test_code_verifier"
        organization = Mock(id=org_id)

        client.create_authorization_url = Mock()
        _ = get_authorization_data(client, code_verifier, organization)

        kwargs = {
             "sign_up": False,
             "locale": "en",
             "ensure_auth": False,
             "organization": org_id,
             "headless": False
        }

        client.create_authorization_url.assert_called_once_with(
             CLI_AUTH, code_verifier=code_verifier, **kwargs)
        
        client.create_authorization_url = Mock()
        _ = get_authorization_data(client, code_verifier, organization=None)

        kwargs = {
             "sign_up": False,
             "locale": "en",
             "ensure_auth":False,
             "headless": False             
        }

        client.create_authorization_url.assert_called_once_with(
             CLI_AUTH, code_verifier=code_verifier, **kwargs)        

    def get_logout_url(self, id_token):
        return f'{CLI_AUTH_LOGOUT}?id_token={id_token}'

    def test_get_logout_url(self):
        id_token = "test_id_token"
        result = get_logout_url(id_token)
        expected_result = f'{CLI_AUTH_LOGOUT}?id_token={id_token}'
        self.assertEqual(result, expected_result)

    def test_get_redirect_url(self):
        self.assertEqual(get_redirect_url(), CLI_CALLBACK)

    def test_get_organization(self):
        with patch.object(main, "CONFIG",
                          (self.assets / Path("config.ini")).absolute()):
            result = get_organization()
            self.assertIsNotNone(result)
            self.assertEqual(result.id, "org_id23423ds")
            self.assertEqual(result.name, "Safety CLI Org")
        