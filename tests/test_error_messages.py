"""
Tests for enhanced error messages - Issue #577
"""
import pytest
from safety.errors import (
    SafetyException,
    SafetyError,
    MalformedDatabase,
    DatabaseFetchError,
    InvalidCredentialError,
    NetworkConnectionError,
    RequestTimeoutError,
    ServerError,
    TooManyRequestsError,
    NotVerifiedEmailError,
    InvalidRequirementError,
)


class TestEnhancedErrorMessages:
    """Test that error messages are clear, helpful, and actionable."""

    def test_safety_exception_provides_context(self):
        """SafetyException should provide clear context about what went wrong."""
        error = SafetyException(info="Connection timeout")
        assert "Connection timeout" in str(error)
        # Should be more descriptive than just "Unhandled exception"
        assert len(str(error)) > 20

    def test_malformed_database_error_is_actionable(self):
        """MalformedDatabase error should guide users on next steps."""
        error = MalformedDatabase(reason="Invalid JSON format", fetched_from="server")
        error_msg = str(error)
        
        # Should mention the source
        assert "server" in error_msg
        # Should include the reason
        assert "Invalid JSON format" in error_msg
        # Should be apologetic and helpful
        assert any(word in error_msg.lower() for word in ["sorry", "wrong"])

    def test_network_connection_error_provides_guidance(self):
        """NetworkConnectionError should help users troubleshoot."""
        error = NetworkConnectionError()
        error_msg = str(error)
        
        # Should mention network/connection
        assert "network" in error_msg.lower() or "connection" in error_msg.lower()
        # Should provide actionable guidance
        assert "check" in error_msg.lower() or "verify" in error_msg.lower()

    def test_invalid_credential_error_includes_help_link(self):
        """InvalidCredentialError should point users to documentation."""
        error = InvalidCredentialError(credential="test-key-123")
        error_msg = str(error)
        
        # Should mention the credential
        assert "test-key-123" in error_msg
        # Should include a help link
        assert "http" in error_msg
        assert "docs" in error_msg.lower() or "support" in error_msg.lower()

    def test_timeout_error_provides_troubleshooting_steps(self):
        """RequestTimeoutError should help users understand what to do."""
        error = RequestTimeoutError()
        error_msg = str(error)
        
        # Should mention timeout
        assert "timeout" in error_msg.lower() or "timed out" in error_msg.lower()
        # Should mention network as potential issue
        assert "network" in error_msg.lower() or "connection" in error_msg.lower()

    def test_server_error_is_reassuring(self):
        """ServerError should reassure users it's not their fault."""
        error = ServerError(reason="Internal server error 500")
        error_msg = str(error)
        
        # Should be apologetic
        assert "sorry" in error_msg.lower() or "wrong" in error_msg.lower()
        # Should mention it's being worked on
        assert any(word in error_msg.lower() for word in ["working", "resolve", "fix"])
        # Should include the reason
        assert "500" in error_msg

    def test_too_many_requests_error_explains_issue(self):
        """TooManyRequestsError should explain rate limiting."""
        error = TooManyRequestsError(reason="Rate limit: 100 requests/hour")
        error_msg = str(error)
        
        # Should mention rate limiting or too many requests
        assert "too many" in error_msg.lower() or "rate" in error_msg.lower()
        # Should include specific reason
        assert "100" in error_msg

    def test_invalid_requirement_error_shows_problematic_line(self):
        """InvalidRequirementError should show which requirement failed."""
        error = InvalidRequirementError(line="invalid==package==version")
        error_msg = str(error)
        
        # Should show the problematic line
        assert "invalid==package==version" in error_msg
        # Should mention parsing/requirement
        assert "parse" in error_msg.lower() or "requirement" in error_msg.lower()

    def test_not_verified_email_error_is_actionable(self):
        """NotVerifiedEmailError should tell users what to do."""
        error = NotVerifiedEmailError()
        error_msg = str(error)
        
        # Should mention email verification
        assert "email" in error_msg.lower()
        assert "verif" in error_msg.lower()

    def test_error_messages_are_user_friendly(self):
        """Error messages should avoid technical jargon where possible."""
        errors_to_test = [
            SafetyException(info="test error"),
            NetworkConnectionError(),
            RequestTimeoutError(),
            ServerError(),
        ]
        
        for error in errors_to_test:
            error_msg = str(error)
            # Should not be empty
            assert len(error_msg) > 0
            # Should use proper capitalization (start with capital letter)
            assert error_msg[0].isupper() or error_msg[0].isdigit()

    def test_error_messages_provide_next_steps(self):
        """Complex errors should provide clear next steps."""
        error = InvalidCredentialError(credential="abc123", reason="Token expired")
        error_msg = str(error)
        
        # Should include the credential
        assert "abc123" in error_msg
        # Should include the reason
        assert "expired" in error_msg.lower()
        # Should have substantial helpful information (not just a one-liner)
        assert len(error_msg) > 50
