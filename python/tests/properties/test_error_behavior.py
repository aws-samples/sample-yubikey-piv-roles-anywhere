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
Property-based tests for error exit behavior.

Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
Validates: Requirements 6.1, 6.2, 6.3, 6.4
"""

import sys
from io import StringIO
from typing import Callable, NoReturn
from unittest.mock import patch, MagicMock

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck, assume

# Import the CLI module
from yubira.cli import (
    EXIT_SUCCESS,
    EXIT_NO_DEVICE,
    EXIT_CONNECTION_FAILED,
    EXIT_NO_CERTIFICATE,
    EXIT_PIN_ERROR,
    EXIT_CERTIFICATE_EXPIRED,
    EXIT_API_ERROR,
    EXIT_NETWORK_ERROR,
    error_exit,
)


# Strategy for error messages (non-empty strings)
error_message_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P', 'S', 'Z')),
    min_size=1,
    max_size=200,
).filter(lambda s: s.strip())

# Strategy for serial numbers
serial_number_strategy = st.integers(min_value=1, max_value=99999999)

# Strategy for slot names
slot_name_strategy = st.sampled_from(["9a", "9c", "9d", "9e"])

# Strategy for retry counts
retry_count_strategy = st.integers(min_value=0, max_value=3)

# Strategy for HTTP status codes (error codes)
http_status_strategy = st.sampled_from([400, 401, 403, 404, 500, 502, 503])


class TestErrorExitBehavior:
    """
    Property 4: Error Exit Behavior
    
    For any error condition (no device, connection failure, PIN blocked, 
    API error), the credential process SHALL exit with a non-zero status 
    code and write a descriptive message to stderr.
    
    Validates: Requirements 6.1, 6.2, 6.3, 6.4
    """

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_no_device_error_exits_nonzero(self, message: str):
        """
        Property: For any YubiKeyNotFoundError, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.1
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_NO_DEVICE)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_NO_DEVICE
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_connection_error_exits_nonzero(self, message: str):
        """
        Property: For any YubiKeyConnectionError, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.2
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_CONNECTION_FAILED)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_CONNECTION_FAILED
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_certificate_error_exits_nonzero(self, message: str):
        """
        Property: For any certificate-related error, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.3
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_NO_CERTIFICATE)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_NO_CERTIFICATE
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_pin_error_exits_nonzero(self, message: str):
        """
        Property: For any PIN-related error, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.4
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_PIN_ERROR)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_PIN_ERROR
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_api_error_exits_nonzero(self, message: str):
        """
        Property: For any API error, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.4
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_API_ERROR)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_API_ERROR
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_network_error_exits_nonzero(self, message: str):
        """
        Property: For any network error, the process SHALL exit 
        with non-zero status and write to stderr.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.4
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, EXIT_NETWORK_ERROR)
        
        # Property: Exit code must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code == EXIT_NETWORK_ERROR
        
        # Property: Error message must be written to stderr
        stderr_output = stderr_capture.getvalue()
        assert len(stderr_output) > 0
        assert "Error:" in stderr_output

    @given(
        exit_code=st.sampled_from([
            EXIT_NO_DEVICE,
            EXIT_CONNECTION_FAILED,
            EXIT_NO_CERTIFICATE,
            EXIT_PIN_ERROR,
            EXIT_CERTIFICATE_EXPIRED,
            EXIT_API_ERROR,
            EXIT_NETWORK_ERROR,
        ]),
        message=error_message_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_all_error_codes_are_nonzero(self, exit_code: int, message: str):
        """
        Property: For any error exit code, the code SHALL be non-zero.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit) as exc_info:
                error_exit(message, exit_code)
        
        # Property: All error exit codes must be non-zero
        assert exc_info.value.code != EXIT_SUCCESS
        assert exc_info.value.code > 0

    @given(message=error_message_strategy)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_error_message_contains_original_message(self, message: str):
        """
        Property: For any error, the stderr output SHALL contain 
        a descriptive message.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit):
                error_exit(message, EXIT_API_ERROR)
        
        stderr_output = stderr_capture.getvalue()
        
        # Property: stderr must contain the error message
        assert message in stderr_output
        
        # Property: stderr must have "Error:" prefix
        assert stderr_output.startswith("Error:")

    @given(
        exit_code=st.sampled_from([
            EXIT_NO_DEVICE,
            EXIT_CONNECTION_FAILED,
            EXIT_NO_CERTIFICATE,
            EXIT_PIN_ERROR,
            EXIT_CERTIFICATE_EXPIRED,
            EXIT_API_ERROR,
            EXIT_NETWORK_ERROR,
        ]),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_error_codes_are_distinct(self, exit_code: int):
        """
        Property: Each error category SHALL have a distinct exit code.
        
        Feature: yubikey-iam-roles-anywhere, Property 4: Error Exit Behavior
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        # Property: All defined error codes must be unique
        all_codes = [
            EXIT_NO_DEVICE,
            EXIT_CONNECTION_FAILED,
            EXIT_NO_CERTIFICATE,
            EXIT_PIN_ERROR,
            EXIT_CERTIFICATE_EXPIRED,
            EXIT_API_ERROR,
            EXIT_NETWORK_ERROR,
        ]
        
        assert len(all_codes) == len(set(all_codes))
        
        # Property: Exit code must be in the defined set
        assert exit_code in all_codes
