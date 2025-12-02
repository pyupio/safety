from unittest.mock import MagicMock, patch
import ssl

from safety.utils.tls import get_system_tls_context


class TestGetSystemContext:
    """
    Tests for get_system_tls_context.
    """

    def test_uses_truststore_when_available(self) -> None:
        mock_truststore = MagicMock()
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_truststore.SSLContext.return_value = mock_context

        with patch.dict("sys.modules", {"truststore": mock_truststore}):
            result = get_system_tls_context()

        assert result == mock_context
        mock_truststore.SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)

    @patch("safety.utils.tls.ssl.create_default_context")
    def test_falls_back_to_ssl_when_truststore_unavailable(
        self, mock_create_context
    ) -> None:
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_create_context.return_value = mock_context

        with patch(
            "builtins.__import__",
            side_effect=ImportError("No module named 'truststore'"),
        ):
            result = get_system_tls_context()

        assert result == mock_context
        mock_create_context.assert_called_once()

    def test_logs_attempt_and_truststore_resolved(self, caplog) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        mock_truststore = MagicMock()
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_truststore.SSLContext.return_value = mock_context

        with patch.dict("sys.modules", {"truststore": mock_truststore}):
            get_system_tls_context()

        # Should log both attempt and resolved with truststore using structured codes
        messages = [record.message for record in caplog.records]
        assert any("config.tls.system_store_attempt" in msg for msg in messages)
        assert any("config.tls.system_store_resolved" in msg for msg in messages)

    def test_logs_attempt_and_fallback(self, caplog) -> None:
        import logging
        import sys

        caplog.set_level(logging.DEBUG)

        # Temporarily remove truststore from sys.modules if present
        truststore_backup = sys.modules.pop("truststore", None)

        try:
            with patch(
                "safety.utils.tls.ssl.create_default_context"
            ) as mock_create_context:
                mock_context = MagicMock(spec=ssl.SSLContext)
                mock_create_context.return_value = mock_context

                # Force ImportError by making import fail
                original_import = __builtins__["__import__"]

                def mock_import(name, *args, **kwargs):
                    if name == "truststore":
                        raise ImportError("No module named 'truststore'")
                    return original_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=mock_import):
                    result = get_system_tls_context()

                assert result == mock_context
        finally:
            # Restore backup
            if truststore_backup:
                sys.modules["truststore"] = truststore_backup

        # Should log both attempt and fallback using structured codes
        messages = [record.message for record in caplog.records]
        assert any("config.tls.system_store_attempt" in msg for msg in messages)
        assert any(
            "config.tls.system_store_unsupported" in msg
            or "config.tls.system_store_resolved" in msg
            for msg in messages
        )
