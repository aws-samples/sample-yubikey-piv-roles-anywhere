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
Unit tests for CLI entry point.

Tests argument parsing, JSON output format, and exit codes for various errors.
Requirements: 5.1, 6.4
"""

import json
import sys
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest

# Import the CLI module
from yubira.cli import (
    init_argparse,
    main,
    error_exit,
    EXIT_SUCCESS,
    EXIT_NO_DEVICE,
    EXIT_CONNECTION_FAILED,
    EXIT_NO_CERTIFICATE,
    EXIT_PIN_ERROR,
    EXIT_API_ERROR,
    EXIT_NETWORK_ERROR,
)


class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_required_arguments(self):
        """Test that required arguments are enforced."""
        parser = init_argparse()
        
        # Missing all required arguments should fail
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_trust_anchor_arn_required(self):
        """Test that --trust-anchor-arn is required."""
        parser = init_argparse()
        
        with pytest.raises(SystemExit):
            parser.parse_args([
                "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/abc",
                "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
            ])

    def test_profile_arn_required(self):
        """Test that --profile-arn is required."""
        parser = init_argparse()
        
        with pytest.raises(SystemExit):
            parser.parse_args([
                "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
                "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
            ])

    def test_role_arn_required(self):
        """Test that --role-arn is required."""
        parser = init_argparse()
        
        with pytest.raises(SystemExit):
            parser.parse_args([
                "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
                "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/abc"
            ])

    def test_all_required_arguments_provided(self):
        """Test parsing with all required arguments."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
        ])
        
        assert args.trust_anchor_arn == "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
        assert args.profile_arn == "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def"
        assert args.role_arn == "arn:aws:iam::123456789012:role/MyRole"

    def test_default_region(self):
        """Test that region defaults to us-east-1."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
        ])
        
        assert args.region == "us-east-1"

    def test_custom_region(self):
        """Test that custom region can be specified."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
            "--region", "eu-west-1"
        ])
        
        assert args.region == "eu-west-1"

    def test_default_slot(self):
        """Test that slot defaults to 9a."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
        ])
        
        assert args.slot == "9a"

    def test_custom_slot(self):
        """Test that custom slot can be specified."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
            "--slot", "9c"
        ])
        
        assert args.slot == "9c"

    def test_serial_number_optional(self):
        """Test that serial number is optional."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
        ])
        
        assert args.serial is None

    def test_serial_number_specified(self):
        """Test that serial number can be specified."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
            "--serial", "12345678"
        ])
        
        assert args.serial == 12345678

    def test_default_session_duration(self):
        """Test that session duration defaults to 3600."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole"
        ])
        
        assert args.session_duration == 3600

    def test_custom_session_duration(self):
        """Test that custom session duration can be specified."""
        parser = init_argparse()
        
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
            "--session-duration", "7200"
        ])
        
        assert args.session_duration == 7200


class TestExitCodes:
    """Tests for CLI exit codes."""

    def test_exit_codes_are_distinct(self):
        """Test that all exit codes are distinct."""
        codes = [
            EXIT_SUCCESS,
            EXIT_NO_DEVICE,
            EXIT_CONNECTION_FAILED,
            EXIT_NO_CERTIFICATE,
            EXIT_PIN_ERROR,
            EXIT_API_ERROR,
            EXIT_NETWORK_ERROR,
        ]
        
        assert len(codes) == len(set(codes))

    def test_success_exit_code_is_zero(self):
        """Test that success exit code is 0."""
        assert EXIT_SUCCESS == 0

    def test_error_exit_codes_are_nonzero(self):
        """Test that all error exit codes are non-zero."""
        error_codes = [
            EXIT_NO_DEVICE,
            EXIT_CONNECTION_FAILED,
            EXIT_NO_CERTIFICATE,
            EXIT_PIN_ERROR,
            EXIT_API_ERROR,
            EXIT_NETWORK_ERROR,
        ]
        
        for code in error_codes:
            assert code != 0
            assert code > 0

    def test_error_exit_writes_to_stderr(self):
        """Test that error_exit writes to stderr."""
        stderr_capture = StringIO()
        
        with patch('sys.stderr', stderr_capture):
            with pytest.raises(SystemExit):
                error_exit("Test error message", EXIT_API_ERROR)
        
        stderr_output = stderr_capture.getvalue()
        assert "Error:" in stderr_output
        assert "Test error message" in stderr_output

    def test_error_exit_returns_correct_code(self):
        """Test that error_exit returns the specified exit code."""
        with patch('sys.stderr', StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                error_exit("Test error", EXIT_NO_DEVICE)
        
        assert exc_info.value.code == EXIT_NO_DEVICE


class TestJSONOutput:
    """Tests for JSON output format."""

    def test_credential_output_is_valid_json(self):
        """Test that credential output is valid JSON."""
        from yubira import AWSCredentials
        
        credentials = AWSCredentials(
            access_key_id="SOME_ACCESSKEYID",
            secret_access_key="SOME_ACCESSSECRETKEY",  # nosec B106 - fake test credential
            session_token="testsessiontoken" * 10,
            expiration=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        )
        
        output = credentials.to_credential_process_output()
        
        # Should be JSON serializable
        json_str = json.dumps(output)
        
        # Should be parseable
        parsed = json.loads(json_str)
        assert parsed == output

    def test_credential_output_has_required_fields(self):
        """Test that credential output has all required fields."""
        from yubira import AWSCredentials
        
        credentials = AWSCredentials(
            access_key_id="SOME_ACCESSKEYID",
            secret_access_key="SOME_ACCESSSECRETKEY",  # nosec B106 - fake test credential
            session_token="testsessiontoken" * 10,
            expiration=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        )
        
        output = credentials.to_credential_process_output()
        
        # Check required fields
        assert "Version" in output
        assert "AccessKeyId" in output
        assert "SecretAccessKey" in output
        assert "SessionToken" in output
        assert "Expiration" in output

    def test_credential_output_version_is_one(self):
        """Test that credential output Version is 1."""
        from yubira import AWSCredentials
        
        credentials = AWSCredentials(
            access_key_id="SOME_ACCESSKEYID",
            secret_access_key="SOME_ACCESSSECRETKEY",  # nosec B106 - fake test credential
            session_token="testsessiontoken" * 10,
            expiration=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        )
        
        output = credentials.to_credential_process_output()
        
        assert output["Version"] == 1

    def test_credential_output_expiration_format(self):
        """Test that expiration is in ISO8601 format with Z suffix."""
        from yubira import AWSCredentials
        
        credentials = AWSCredentials(
            access_key_id="SOME_ACCESSKEYID",
            secret_access_key="SOME_ACCESSSECRETKEY",  # nosec B106 - fake test credential
            session_token="testsessiontoken" * 10,
            expiration=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        )
        
        output = credentials.to_credential_process_output()
        
        # Should end with Z
        assert output["Expiration"].endswith("Z")
        
        # Should be parseable as ISO8601
        expiration_str = output["Expiration"]
        parsed = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
        assert parsed.year == 2024
        assert parsed.month == 12
        assert parsed.day == 31
