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
Unit tests for Roles Anywhere Client.

Tests request body construction, response parsing, and error handling.
Requirements: 4.1, 4.2, 4.3
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, Mock

import pytest
import requests

from yubira.roles_anywhere_client import (
    RolesAnywhereClient,
    AWSCredentials,
    RolesAnywhereError,
    RolesAnywhereAPIError,
    RolesAnywhereNetworkError,
)
from yubira.request_signer import RequestSigner, SignedRequest


class TestAWSCredentials:
    """Tests for AWSCredentials dataclass. Requirements: 4.2, 5.1, 5.2"""

    def test_to_credential_process_output_has_version_one(self):
        """Test that output has Version field equal to 1."""
        credentials = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # nosec B106 - fake test credential
            session_token="FwoGZXIvYXdzEBYaDK...",
            expiration=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        
        output = credentials.to_credential_process_output()
        
        assert output["Version"] == 1
        assert isinstance(output["Version"], int)

    def test_to_credential_process_output_has_all_required_fields(self):
        """Test that output contains all required fields."""
        credentials = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # nosec B106 - fake test credential
            session_token="FwoGZXIvYXdzEBYaDK...",
            expiration=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        
        output = credentials.to_credential_process_output()
        
        required_fields = {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
        assert set(output.keys()) == required_fields

    def test_to_credential_process_output_preserves_credentials(self):
        """Test that credential values are preserved in output."""
        credentials = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # nosec B106 - fake test credential
            session_token="FwoGZXIvYXdzEBYaDK...",
            expiration=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        
        output = credentials.to_credential_process_output()
        
        assert output["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
        assert output["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert output["SessionToken"] == "FwoGZXIvYXdzEBYaDK..."

    def test_to_credential_process_output_expiration_is_iso8601_with_z(self):
        """Test that expiration is formatted as ISO8601 with Z suffix."""
        credentials = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="secret",  # nosec B106 - fake test credential
            session_token="token",
            expiration=datetime(2024, 1, 15, 12, 30, 45, tzinfo=timezone.utc),
        )
        
        output = credentials.to_credential_process_output()
        
        assert output["Expiration"].endswith("Z")
        assert "2024-01-15T12:30:45" in output["Expiration"]

    def test_to_credential_process_output_is_json_serializable(self):
        """Test that output can be serialized to JSON."""
        credentials = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="secret",  # nosec B106 - fake test credential
            session_token="token",
            expiration=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        
        output = credentials.to_credential_process_output()
        
        # Should not raise
        json_str = json.dumps(output)
        parsed = json.loads(json_str)
        assert parsed == output


class TestRolesAnywhereClientRequestBody:
    """Tests for request body construction. Requirements: 4.1"""

    def test_build_request_body_contains_duration_seconds(self):
        """Test that request body contains durationSeconds."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            session_duration=7200,
        )
        
        body = client._build_request_body()
        
        assert body["durationSeconds"] == 7200

    def test_build_query_string_contains_profile_arn(self):
        """Test that query string contains profileArn."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        query_string = client._build_query_string()
        
        assert "profileArn=" in query_string
        assert "profile%2Fdef" in query_string  # URL-encoded

    def test_build_query_string_contains_role_arn(self):
        """Test that query string contains roleArn."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        query_string = client._build_query_string()
        
        assert "roleArn=" in query_string
        assert "role%2FTestRole" in query_string  # URL-encoded

    def test_build_query_string_contains_trust_anchor_arn(self):
        """Test that query string contains trustAnchorArn."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        query_string = client._build_query_string()
        
        assert "trustAnchorArn=" in query_string
        assert "trust-anchor%2Fabc" in query_string  # URL-encoded

    def test_build_request_body_default_duration(self):
        """Test that default session duration is 3600 seconds."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        body = client._build_request_body()
        
        assert body["durationSeconds"] == 3600


class TestRolesAnywhereClientHeaders:
    """Tests for request header construction. Requirements: 4.1"""

    def test_build_headers_contains_host(self):
        """Test that headers contain Host."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-west-2:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            region="us-west-2",
        )
        
        headers = client._build_headers(
            certificate_der=b"test cert",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            content_length=100,
        )
        
        assert headers["Host"] == "rolesanywhere.us-west-2.amazonaws.com"

    def test_build_headers_contains_content_type(self):
        """Test that headers contain Content-Type."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        headers = client._build_headers(
            certificate_der=b"test cert",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            content_length=100,
        )
        
        assert headers["Content-Type"] == "application/json"

    def test_build_headers_contains_x_amz_date(self):
        """Test that headers contain X-Amz-Date in correct format."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        headers = client._build_headers(
            certificate_der=b"test cert",
            timestamp=datetime(2024, 1, 15, 12, 30, 45),
            content_length=100,
        )
        
        assert headers["X-Amz-Date"] == "20240115T123045Z"

    def test_build_headers_contains_x_amz_x509(self):
        """Test that headers contain X-Amz-X509 with base64 encoded cert."""
        import base64
        
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        cert_der = b"test certificate data"
        headers = client._build_headers(
            certificate_der=cert_der,
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            content_length=100,
        )
        
        expected_b64 = base64.b64encode(cert_der).decode("ascii")
        assert headers["X-Amz-X509"] == expected_b64

    def test_build_headers_contains_content_length(self):
        """Test that headers contain Content-Length."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        headers = client._build_headers(
            certificate_der=b"test cert",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            content_length=256,
        )
        
        assert headers["Content-Length"] == "256"


class TestRolesAnywhereClientResponseParsing:
    """Tests for response parsing. Requirements: 4.2"""

    def test_parse_response_success(self):
        """Test parsing a successful API response."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                "credentials": {
                    "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # nosec B106 - fake test credential
                    "sessionToken": "tokenXXX",
                    "expiration": "2024-01-15T13:00:00Z"
                }
            }]
        }
        
        credentials = client._parse_response(mock_response)
        
        assert credentials.access_key_id == "ASIAIOSFODNN7EXAMPLE"
        assert credentials.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec B105 - fake test credential
        assert credentials.session_token == "tokenXXX"  # nosec B105 - fake test credential
        assert credentials.expiration.year == 2024
        assert credentials.expiration.month == 1
        assert credentials.expiration.day == 15

    def test_parse_response_error_status_code(self):
        """Test parsing an error response."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "message": "Invalid trust anchor ARN",
            "code": "ValidationException"
        }
        
        with pytest.raises(RolesAnywhereAPIError) as exc_info:
            client._parse_response(mock_response)
        
        assert "Invalid trust anchor ARN" in str(exc_info.value)
        assert exc_info.value.status_code == 400
        assert exc_info.value.error_code == "ValidationException"

    def test_parse_response_empty_credential_set(self):
        """Test parsing response with empty credential set."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"credentialSet": []}
        
        with pytest.raises(RolesAnywhereAPIError) as exc_info:
            client._parse_response(mock_response)
        
        assert "No credentials returned" in str(exc_info.value)

    def test_parse_response_missing_credentials_field(self):
        """Test parsing response with missing credentials field."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                "credentials": {
                    "accessKeyId": "ASIAXXX",
                    # Missing secretAccessKey, sessionToken, expiration
                }
            }]
        }
        
        with pytest.raises(RolesAnywhereAPIError) as exc_info:
            client._parse_response(mock_response)
        
        assert "Incomplete credentials" in str(exc_info.value)

    def test_parse_response_invalid_json(self):
        """Test parsing response with invalid JSON."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("test", "doc", 0)
        
        with pytest.raises(RolesAnywhereAPIError) as exc_info:
            client._parse_response(mock_response)
        
        assert "Invalid JSON" in str(exc_info.value)

    def test_parse_response_rejects_mismatched_role(self):
        """Test credentials are bound to the requested role identity."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/OtherRole",
                "credentials": {
                    "accessKeyId": "ASIAXXX",
                    "secretAccessKey": "synthetic-secret",
                    "sessionToken": "synthetic-token",
                    "expiration": "2030-01-15T13:00:00Z",
                },
            }]
        }

        with pytest.raises(RolesAnywhereAPIError, match="does not match"):
            client._parse_response(mock_response)



class TestRolesAnywhereClientErrorHandling:
    """Tests for error handling. Requirements: 4.3"""

    @patch("yubira.roles_anywhere_client.requests.post")
    def test_create_session_network_timeout(self, mock_post):
        """Test handling of network timeout."""
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")
        
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_signer = MagicMock(spec=RequestSigner)
        mock_signer.sign_request.return_value = SignedRequest(
            method="POST",
            uri="/sessions",
            headers={"Host": "test"},
            body=b"{}",
            signature=b"sig",
        )
        
        with pytest.raises(RolesAnywhereNetworkError) as exc_info:
            client.create_session(b"cert", mock_signer)
        
        assert "timed out" in str(exc_info.value)

    @patch("yubira.roles_anywhere_client.requests.post")
    def test_create_session_connection_error(self, mock_post):
        """Test handling of connection error."""
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_signer = MagicMock(spec=RequestSigner)
        mock_signer.sign_request.return_value = SignedRequest(
            method="POST",
            uri="/sessions",
            headers={"Host": "test"},
            body=b"{}",
            signature=b"sig",
        )
        
        with pytest.raises(RolesAnywhereNetworkError) as exc_info:
            client.create_session(b"cert", mock_signer)
        
        assert "Connection error" in str(exc_info.value)

    @patch("yubira.roles_anywhere_client.requests.post")
    def test_create_session_api_error(self, mock_post):
        """Test handling of API error response."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "message": "Access denied",
            "code": "AccessDeniedException"
        }
        mock_post.return_value = mock_response
        
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_signer = MagicMock(spec=RequestSigner)
        mock_signer.sign_request.return_value = SignedRequest(
            method="POST",
            uri="/sessions",
            headers={"Host": "test"},
            body=b"{}",
            signature=b"sig",
        )
        
        with pytest.raises(RolesAnywhereAPIError) as exc_info:
            client.create_session(b"cert", mock_signer)
        
        assert "Access denied" in str(exc_info.value)
        assert exc_info.value.status_code == 403

    @patch("yubira.roles_anywhere_client.requests.post")
    def test_create_session_success(self, mock_post):
        """Test successful create_session call."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                "credentials": {
                    "accessKeyId": "ASIAXXX",
                    "secretAccessKey": "secretXXX",  # nosec B106 - fake test credential
                    "sessionToken": "tokenXXX",
                    "expiration": "2024-01-15T13:00:00Z"
                }
            }]
        }
        mock_post.return_value = mock_response
        
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        mock_signer = MagicMock(spec=RequestSigner)
        mock_signer.sign_request.return_value = SignedRequest(
            method="POST",
            uri="/sessions",
            headers={"Host": "test"},
            body=b"{}",
            signature=b"sig",
        )
        
        credentials = client.create_session(b"cert", mock_signer)
        
        assert credentials.access_key_id == "ASIAXXX"
        assert credentials.secret_access_key == "secretXXX"  # nosec B105 - fake test credential


class TestRolesAnywhereClientEndpoint:
    """Tests for endpoint construction."""

    def test_endpoint_uses_region(self):
        """Test that endpoint includes the configured region."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-west-2:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            region="us-west-2",
        )
        
        assert client.endpoint == "https://rolesanywhere.us-west-2.amazonaws.com"

    def test_host_uses_region(self):
        """Test that host includes the configured region."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:eu-west-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            region="eu-west-1",
        )
        
        assert client.host == "rolesanywhere.eu-west-1.amazonaws.com"

    def test_default_region_is_us_east_1(self):
        """Test that default region is us-east-1."""
        client = RolesAnywhereClient(
            trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        
        assert "us-east-1" in client.endpoint
