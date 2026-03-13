"""
MIT No Attribution
Copyright 2026 AWS

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
"""
Unit tests for PIN Handler.

Tests environment variable reading, retry count tracking, and PIN blocked detection.
Requirements: 2.2, 2.3, 2.4
"""

import os
from unittest.mock import patch, MagicMock

import pytest

from yubira.pin_handler import (
    PinHandler,
    PinResult,
    PinSource,
    PinError,
    PinBlockedError,
    PinRequiredError,
)


class TestGetPin:
    """Tests for PIN retrieval functionality. Requirements: 2.2"""

    def test_get_pin_from_environment_variable(self):
        """Test that get_pin reads PIN from environment variable."""
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        with patch.dict(os.environ, {PinHandler.ENV_VAR: "123456"}):
            pin = handler.get_pin(source=PinSource.ENVIRONMENT)
            assert pin == "123456"

    def test_get_pin_raises_when_env_var_not_set(self):
        """Test that get_pin raises PinRequiredError when env var not set."""
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        # Ensure the env var is not set
        env = os.environ.copy()
        env.pop(PinHandler.ENV_VAR, None)
        
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(PinRequiredError) as exc_info:
                handler.get_pin(source=PinSource.ENVIRONMENT)
            
            assert PinHandler.ENV_VAR in str(exc_info.value)

    def test_get_pin_from_prompt(self):
        """Test that get_pin prompts user when source is PROMPT."""
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        with patch('yubira.pin_handler.getpass.getpass', return_value="654321"):
            pin = handler.get_pin(source=PinSource.PROMPT)
            assert pin == "654321"

    def test_get_pin_auto_prefers_environment(self):
        """Test that get_pin_auto uses environment variable when available."""
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        with patch.dict(os.environ, {PinHandler.ENV_VAR: "env_pin"}):
            pin, source = handler.get_pin_auto()
            assert pin == "env_pin"
            assert source == PinSource.ENVIRONMENT

    def test_get_pin_auto_falls_back_to_prompt(self):
        """Test that get_pin_auto prompts when env var not set."""
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        env = os.environ.copy()
        env.pop(PinHandler.ENV_VAR, None)
        
        with patch.dict(os.environ, env, clear=True):
            with patch('yubira.pin_handler.getpass.getpass', return_value="prompt_pin"):
                pin, source = handler.get_pin_auto()
                assert pin == "prompt_pin"
                assert source == PinSource.PROMPT


class TestVerifyPin:
    """Tests for PIN verification functionality. Requirements: 2.3, 2.4"""

    def test_verify_pin_success(self):
        """Test successful PIN verification."""
        mock_session = MagicMock()
        mock_session.verify_pin.return_value = None  # Success returns None
        handler = PinHandler(mock_session)
        
        result = handler.verify_pin("123456")
        
        assert result.success is True
        mock_session.verify_pin.assert_called_once_with("123456")

    def test_verify_pin_incorrect_with_retries(self):
        """Test incorrect PIN returns failure with retry count."""
        mock_session = MagicMock()
        mock_session.verify_pin.side_effect = Exception("Wrong PIN, 2 retries remaining")
        handler = PinHandler(mock_session)
        
        result = handler.verify_pin("wrong_pin")
        
        assert result.success is False
        assert result.retries_remaining == 2
        assert "Incorrect PIN" in result.error_message

    def test_verify_pin_blocked_raises_error(self):
        """Test that blocked PIN raises PinBlockedError."""
        mock_session = MagicMock()
        mock_session.verify_pin.side_effect = Exception("PIN is blocked")
        handler = PinHandler(mock_session)
        
        with pytest.raises(PinBlockedError) as exc_info:
            handler.verify_pin("any_pin")
        
        assert "blocked" in str(exc_info.value).lower()

    def test_verify_pin_zero_retries_raises_blocked(self):
        """Test that zero retries remaining raises PinBlockedError."""
        mock_session = MagicMock()
        mock_session.verify_pin.side_effect = Exception("Wrong PIN, 0 retries remaining")
        handler = PinHandler(mock_session)
        
        with pytest.raises(PinBlockedError):
            handler.verify_pin("wrong_pin")


class TestRetryTracking:
    """Tests for retry count tracking. Requirements: 2.3"""

    def test_get_retries_remaining(self):
        """Test getting remaining PIN retries."""
        mock_session = MagicMock()
        mock_session.get_pin_attempts.return_value = 3
        handler = PinHandler(mock_session)
        
        retries = handler.get_retries_remaining()
        
        assert retries == 3
        mock_session.get_pin_attempts.assert_called_once()

    def test_get_retries_returns_negative_on_error(self):
        """Test that get_retries_remaining returns -1 on error."""
        mock_session = MagicMock()
        mock_session.get_pin_attempts.side_effect = Exception("Error")
        handler = PinHandler(mock_session)
        
        retries = handler.get_retries_remaining()
        
        assert retries == -1

    def test_extract_retries_various_formats(self):
        """Test retry extraction from various error message formats."""
        # Test different message formats
        test_cases = [
            ("Wrong PIN, 3 retries remaining", 3),
            ("2 attempts remaining", 2),
            ("1 retry left", 1),
            ("retries remaining: 5", 5),
            ("attempts left: 4", 4),
            ("No retry info here", None),
        ]
        
        for message, expected in test_cases:
            result = PinHandler._extract_retries(message)
            assert result == expected, f"Failed for message: {message}"


class TestPinRequired:
    """Tests for PIN requirement checking."""

    def test_is_pin_required_returns_true(self):
        """Test that is_pin_required returns True for PIV slots."""
        from yubikit.piv import SLOT
        
        mock_session = MagicMock()
        handler = PinHandler(mock_session)
        
        # PIN is required for all standard PIV slots
        assert handler.is_pin_required(SLOT.AUTHENTICATION) is True
        assert handler.is_pin_required(SLOT.SIGNATURE) is True
        assert handler.is_pin_required(SLOT.KEY_MANAGEMENT) is True
