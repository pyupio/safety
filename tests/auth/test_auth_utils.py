import unittest
from unittest.mock import MagicMock, Mock, patch, call

from safety.auth.utils import initialize, extract_detail, FeatureType, \
    str_to_bool, get_config_setting, save_flags_config
from safety.errors import InvalidCredentialError


class TestUtils(unittest.TestCase):

    @patch('safety.auth.utils.get_config_setting')
    @patch('safety.auth.utils.str_to_bool')
    @patch('safety.auth.utils.save_flags_config')
    def test_initialize_with_no_session(
            self,
            mock_save_flags_config,
            mock_str_to_bool,
            mock_get_config_setting):

        ctx = Mock()
        ctx.obj = None
        mock_get_config_setting.return_value = 'true'
        mock_str_to_bool.return_value = True

        # First test: when auth is None
        with patch('safety.models.SafetyCLI') as MockSafetyCLI:
            mock_safety_cli = Mock()
            mock_safety_cli.auth = None
            MockSafetyCLI.return_value = mock_safety_cli
            
            initialize(ctx, refresh=True)
            
            # Verify expected behavior when auth is None
            mock_save_flags_config.assert_not_called()
            self.assertEqual(mock_get_config_setting.call_count, len(FeatureType))

        # Reset mock call counts
        mock_get_config_setting.reset_mock()
        mock_save_flags_config.reset_mock()

        # Second test: when auth is populated but raises exception
        ctx = Mock()
        mock_safety_cli = Mock()

        mock_initialize = Mock(side_effect=InvalidCredentialError())
        mock_client = Mock()
        mock_client.initialize = mock_initialize
        mock_auth = Mock()
        mock_auth.client = mock_client
        mock_safety_cli.auth = mock_auth
        ctx.obj = mock_safety_cli

        initialize(ctx, refresh=True)
        
        # On exception, it should fall back to default values
        mock_safety_cli.auth.client.initialize.assert_called_once()
        mock_save_flags_config.assert_not_called()
        self.assertEqual(mock_get_config_setting.call_count, len(FeatureType))

    @patch('safety.auth.utils.get_config_setting')
    @patch('safety.auth.utils.str_to_bool')
    @patch('safety.auth.utils.save_flags_config')
    def test_initialize_without_refresh(self,
                                        mock_save_flags_config,
                                        mock_str_to_bool,
                                        mock_get_config_setting):
        ctx = MagicMock()
        ctx.obj = None
        mock_get_config_setting.return_value = 'true'
        mock_str_to_bool.return_value = True

        with patch('safety.auth.utils.SafetyCLI') as MockSafetyCLI, \
             patch('safety.auth.utils.setattr') as mock_setattr:
            
            mock_safety_cli = MockSafetyCLI.return_value

            initialize(ctx, refresh=False)

            mock_safety_cli.auth.client.initialize.assert_not_called()
            mock_save_flags_config.assert_not_called()
            self.assertEqual(mock_get_config_setting.call_count,
                             len(FeatureType))
            
            expected_calls = [
                call(mock_safety_cli, feature.attr_name, True)
                for feature in FeatureType
            ]
            mock_setattr.assert_has_calls(expected_calls, any_order=True)
            
            # Verify number of calls matches number of features
            self.assertEqual(mock_setattr.call_count, len(FeatureType))


    @patch('safety.auth.utils.get_config_setting')
    @patch('safety.auth.utils.save_flags_config')
    def test_initialize_with_server_response(self, 
                                             mock_save_flags_config, 
                                             mock_get_config_setting):

        ctx = Mock()
        mock_safety_cli = Mock()

        SERVER_RESPONSE = {
            "organization": "Test",
            "plan": {},
            "firewall-enabled": "false",
            "platform-enabled": "true",
            "events-enabled": "false"
        }

        mock_initialize = Mock(
            return_value={"organization": "Test",
                          "plan": {},
                          "firewall-enabled": "false",
                          "platform-enabled": "true",
                          "events-enabled": "false"})
        mock_client = Mock()
        mock_client.initialize = mock_initialize
        mock_auth = Mock()
        mock_auth.client = mock_client
        mock_safety_cli.auth = mock_auth
        ctx.obj = mock_safety_cli

        with patch('safety.auth.utils.setattr') as mock_setattr:        

            initialize(ctx, refresh=True)
            
            mock_safety_cli.auth.client.initialize.assert_called_once()
            mock_save_flags_config.assert_called_once()
            self.assertEqual(mock_get_config_setting.call_count,
                             len(FeatureType))

            # Server response should override current values
            expected_calls = [
                call(mock_safety_cli,
                     feature.attr_name, 
                     str_to_bool(SERVER_RESPONSE[feature.config_key]))
                for feature in FeatureType
            ]
            mock_setattr.assert_has_calls(expected_calls, any_order=True)
            
            # Verify number of calls matches number of features
            self.assertEqual(mock_setattr.call_count, len(FeatureType))

    def test_extract_detail(self):
        # Test valid JSON with detail
        response = Mock()
        response.json.return_value = {"detail": "Error message"}
        detail = extract_detail(response)
        self.assertEqual(detail, "Error message")

        # Test valid JSON without detail
        response.json.return_value = {"message": "Something else"}
        detail = extract_detail(response)
        self.assertIsNone(detail)

        # Test invalid JSON
        response.json.side_effect = ValueError()
        detail = extract_detail(response)
        self.assertIsNone(detail)

        # Test empty response
        response.json.side_effect = None
        response.json.return_value = {}
