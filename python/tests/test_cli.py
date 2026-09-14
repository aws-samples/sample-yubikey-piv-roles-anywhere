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
    EXIT_CERTIFICATE_EXPIRED,
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

    def test_certificate_chain_is_optional(self):
        parser = init_argparse()
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
        ])
        assert args.certificate_chain is None

    def test_certificate_chain_path_is_accepted(self):
        parser = init_argparse()
        args = parser.parse_args([
            "--trust-anchor-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "--profile-arn", "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "--role-arn", "arn:aws:iam::123456789012:role/MyRole",
            "--certificate-chain", "intermediates.pem",
        ])
        assert args.certificate_chain == "intermediates.pem"


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


class TestErrorRedaction:
    """Internal exception text must not cross the CLI stderr boundary."""

    CLI_ARGS = [
        "yubira",
        "--trust-anchor-arn",
        "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/example",
        "--profile-arn",
        "arn:aws:rolesanywhere:us-east-1:123456789012:profile/example",
        "--role-arn",
        "arn:aws:iam::123456789012:role/ExampleRole",
    ]
    SENSITIVE_DETAIL = "synthetic-sensitive-internal-detail"

    def _invoke(self, connector, *patches):
        from contextlib import ExitStack

        stderr_capture = StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, "argv", self.CLI_ARGS))
            stack.enter_context(
                patch("yubira.cli.YubiKeyConnector", return_value=connector)
            )
            stack.enter_context(patch("sys.stderr", stderr_capture))
            for patcher in patches:
                stack.enter_context(patcher)
            exc_info = stack.enter_context(pytest.raises(SystemExit))
            main()
        return exc_info.value.code, stderr_capture.getvalue()

    def test_connection_error_details_are_redacted(self):
        from yubira import YubiKeyConnectionError

        connector = MagicMock()
        connector.connect.side_effect = YubiKeyConnectionError(self.SENSITIVE_DETAIL)

        code, stderr = self._invoke(connector)

        assert code == EXIT_CONNECTION_FAILED
        assert stderr == "Error: Failed to connect to YubiKey.\n"
        assert self.SENSITIVE_DETAIL not in stderr

    def test_certificate_error_details_are_redacted(self):
        from yubira import CertificateReadError

        connector = MagicMock()
        reader = MagicMock()
        reader.read_certificate.side_effect = CertificateReadError(self.SENSITIVE_DETAIL)

        code, stderr = self._invoke(
            connector,
            patch("yubira.cli.CertificateReader", return_value=reader),
        )

        assert code == EXIT_NO_CERTIFICATE
        assert stderr == "Error: Failed to read certificate.\n"
        assert self.SENSITIVE_DETAIL not in stderr

    @pytest.mark.parametrize(
        ("exception_type", "expected_code", "expected_message"),
        [
            ("signing", EXIT_API_ERROR, "Error: Signing failed.\n"),
            ("api", EXIT_API_ERROR, "Error: CreateSession request failed.\n"),
            ("network", EXIT_NETWORK_ERROR, "Error: Network request failed.\n"),
        ],
    )
    def test_session_error_details_are_redacted(
        self, exception_type, expected_code, expected_message
    ):
        from yubira import SigningError, RolesAnywhereAPIError, RolesAnywhereNetworkError

        exceptions = {
            "signing": SigningError(self.SENSITIVE_DETAIL),
            "api": RolesAnywhereAPIError(self.SENSITIVE_DETAIL),
            "network": RolesAnywhereNetworkError(self.SENSITIVE_DETAIL),
        }
        connector = MagicMock()
        cert_info = MagicMock()
        cert_info.is_expired = False
        reader = MagicMock()
        reader.read_certificate.return_value = cert_info
        pin_handler = MagicMock()
        pin_handler.is_pin_required.return_value = False
        client = MagicMock()
        client.create_session.side_effect = exceptions[exception_type]

        code, stderr = self._invoke(
            connector,
            patch("yubira.cli.CertificateReader", return_value=reader),
            patch("yubira.cli.PinHandler", return_value=pin_handler),
            patch("yubira.cli.RolesAnywhereClient", return_value=client),
        )

        assert code == expected_code
        assert stderr == expected_message
        assert self.SENSITIVE_DETAIL not in stderr

    def test_unexpected_error_details_are_redacted(self):
        connector = MagicMock()
        connector.get_piv_session.side_effect = RuntimeError(self.SENSITIVE_DETAIL)

        code, stderr = self._invoke(connector)

        assert code == EXIT_API_ERROR
        assert stderr == "Error: Unexpected internal error.\n"
        assert self.SENSITIVE_DETAIL not in stderr

    def test_invalid_configuration_is_rejected_before_token_access(self):
        args = [*self.CLI_ARGS, "--region", "x/"]
        stderr_capture = StringIO()
        with (
            patch.object(sys, "argv", args),
            patch("yubira.cli.YubiKeyConnector") as connector_class,
            patch("sys.stderr", stderr_capture),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        assert exc_info.value.code == EXIT_API_ERROR
        assert "Invalid configuration: region has invalid syntax" in stderr_capture.getvalue()
        connector_class.assert_not_called()

    def test_multiple_tokens_require_optional_serial_parameter(self):
        from yubira import MultipleYubiKeysError

        connector = MagicMock()
        connector.connect.side_effect = MultipleYubiKeysError("untrusted detail")

        code, stderr = self._invoke(connector)

        assert code == EXIT_CONNECTION_FAILED
        assert stderr == "Error: Multiple YubiKeys detected. Specify --serial.\n"
        assert "untrusted detail" not in stderr

    def test_not_yet_valid_certificate_is_rejected_before_pin(self):
        connector = MagicMock()
        cert_info = MagicMock()
        cert_info.is_expired = False
        cert_info.is_not_yet_valid = True
        cert_info.not_before = datetime(2030, 1, 2, tzinfo=timezone.utc)
        reader = MagicMock()
        reader.read_certificate.return_value = cert_info
        pin_handler_class = MagicMock()

        code, stderr = self._invoke(
            connector,
            patch("yubira.cli.CertificateReader", return_value=reader),
            patch("yubira.cli.PinHandler", pin_handler_class),
        )

        assert code == EXIT_CERTIFICATE_EXPIRED
        assert stderr == "Error: Certificate is not valid before 2030-01-02.\n"
        pin_handler_class.assert_not_called()
