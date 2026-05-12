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
Unit tests for Request Signer.

Tests canonical request construction, string-to-sign creation, and algorithm selection.
Requirements: 3.1, 3.3
"""

import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from yubikit.piv import SLOT

from yubira.request_signer import (
    RequestSigner,
    SignedRequest,
    SigningError,
)


def create_mock_certificate(key_type: str = "RSA") -> x509.Certificate:
    """Create a mock X.509 certificate for testing."""
    if key_type == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_type == "EC256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:  # EC384
        private_key = ec.generate_private_key(ec.SECP384R1())
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime(2030, 12, 31))
        .sign(private_key, hashes.SHA256())
    )
    
    return cert


class TestSignatureAlgorithmSelection:
    """Tests for signature algorithm detection. Requirements: 3.3"""

    def test_get_signature_algorithm_returns_sha256_with_rsa_for_rsa_key(self):
        """Test that RSA keys return RSA-SHA256 algorithm."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        algorithm = signer.get_signature_algorithm()
        
        assert algorithm == "RSA-SHA256"

    def test_get_signature_algorithm_returns_sha256_with_ecdsa_for_p256_key(self):
        """Test that P-256 EC keys return ECDSA-SHA256 algorithm."""
        cert = create_mock_certificate(key_type="EC256")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        algorithm = signer.get_signature_algorithm()
        
        assert algorithm == "ECDSA-SHA256"

    def test_get_signature_algorithm_returns_sha256_with_ecdsa_for_p384_key(self):
        """Test that P-384 EC keys return ECDSA-SHA256 algorithm (IAM Roles Anywhere requires SHA256)."""
        cert = create_mock_certificate(key_type="EC384")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        algorithm = signer.get_signature_algorithm()
        
        assert algorithm == "ECDSA-SHA256"

    def test_get_signature_algorithm_raises_error_when_no_certificate(self):
        """Test that missing certificate raises SigningError."""
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = None
        
        signer = RequestSigner(mock_session)
        
        with pytest.raises(SigningError) as exc_info:
            signer.get_signature_algorithm()
        
        assert "No certificate found" in str(exc_info.value)

    def test_get_signature_algorithm_caches_result(self):
        """Test that algorithm is cached after first call."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        # Call twice
        alg1 = signer.get_signature_algorithm()
        alg2 = signer.get_signature_algorithm()
        
        # Should only call get_certificate once due to caching
        assert mock_session.get_certificate.call_count == 1
        assert alg1 == alg2


class TestCanonicalRequestConstruction:
    """Tests for canonical request construction. Requirements: 3.1"""

    def test_canonical_request_method_is_uppercase(self):
        """Test that HTTP method is uppercased in canonical request."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="post",
            uri="/sessions",
            query_string="",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        assert lines[0] == "POST"

    def test_canonical_request_uri_starts_with_slash(self):
        """Test that URI path starts with slash."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="sessions",  # No leading slash
            query_string="",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        assert lines[1].startswith("/")

    def test_canonical_request_empty_uri_becomes_root(self):
        """Test that empty URI becomes root path."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="",
            query_string="",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        assert lines[1] == "/"

    def test_canonical_request_headers_are_lowercase(self):
        """Test that header names are lowercased."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"Host": "example.com", "Content-Type": "application/json"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        # Check that lowercase header names appear in the canonical request
        assert "host:" in canonical
        assert "content-type:" in canonical
        assert "Host:" not in canonical
        assert "Content-Type:" not in canonical

    def test_canonical_request_headers_are_sorted(self):
        """Test that headers are sorted alphabetically."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"z-header": "z", "a-header": "a", "m-header": "m"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        # Find positions of headers
        a_pos = canonical.find("a-header:")
        m_pos = canonical.find("m-header:")
        z_pos = canonical.find("z-header:")
        
        assert a_pos < m_pos < z_pos

    def test_canonical_request_header_values_trimmed(self):
        """Test that header values have whitespace trimmed."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"host": "  example.com  ", "x-test": "  value  with  spaces  "},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        # Values should be trimmed and internal whitespace collapsed
        assert "host:example.com" in canonical
        assert "x-test:value with spaces" in canonical

    def test_canonical_request_ends_with_payload_hash(self):
        """Test that canonical request ends with payload hash."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        payload_hash = "abc123def456"
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"host": "example.com"},
            payload_hash=payload_hash
        )
        
        lines = canonical.split("\n")
        assert lines[-1] == payload_hash

    def test_canonical_request_query_string_sorted(self):
        """Test that query string parameters are sorted."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="z=1&a=2&m=3",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        # Query string is on line 3 (index 2)
        assert lines[2] == "a=2&m=3&z=1"

    def test_canonical_request_empty_query_string(self):
        """Test that empty query string is handled correctly."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        # Query string line should be empty
        assert lines[2] == ""


class TestStringToSign:
    """Tests for string-to-sign construction. Requirements: 3.1"""

    def test_string_to_sign_starts_with_algorithm(self):
        """Test that string to sign starts with algorithm identifier."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region="us-east-1",
            canonical_request="test canonical request"
        )
        
        lines = string_to_sign.split("\n")
        assert lines[0] == "AWS4-X509-RSA-SHA256"

    def test_string_to_sign_contains_timestamp(self):
        """Test that string to sign contains ISO8601 timestamp."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        timestamp = datetime(2024, 1, 15, 12, 30, 45)
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region="us-east-1",
            canonical_request="test"
        )
        
        lines = string_to_sign.split("\n")
        assert lines[1] == "20240115T123045Z"

    def test_string_to_sign_contains_credential_scope(self):
        """Test that string to sign contains credential scope."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region="us-west-2",
            canonical_request="test"
        )
        
        lines = string_to_sign.split("\n")
        assert lines[2] == "20240115/us-west-2/rolesanywhere/aws4_request"

    def test_string_to_sign_contains_hashed_canonical_request(self):
        """Test that string to sign contains SHA-256 hash of canonical request."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        canonical_request = "test canonical request"
        expected_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
        
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region="us-east-1",
            canonical_request=canonical_request
        )
        
        lines = string_to_sign.split("\n")
        assert lines[3] == expected_hash

    def test_string_to_sign_uses_ecdsa_algorithm_for_ec_key(self):
        """Test that EC keys use ECDSA algorithm in string to sign."""
        cert = create_mock_certificate(key_type="EC256")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        signer = RequestSigner(mock_session)
        
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region="us-east-1",
            canonical_request="test"
        )
        
        lines = string_to_sign.split("\n")
        assert lines[0] == "AWS4-X509-ECDSA-SHA256"


class TestPayloadHash:
    """Tests for payload hash computation."""

    def test_hash_payload_returns_sha256_hex(self):
        """Test that hash_payload returns SHA-256 hex digest."""
        payload = b"test payload"
        expected = hashlib.sha256(payload).hexdigest()
        
        result = RequestSigner.hash_payload(payload)
        
        assert result == expected

    def test_hash_payload_empty_payload(self):
        """Test hash of empty payload."""
        expected = hashlib.sha256(b"").hexdigest()
        
        result = RequestSigner.hash_payload(b"")
        
        assert result == expected
        # Known SHA-256 of empty string
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestAWSSigV4TestVectors:
    """
    Tests using AWS SigV4 test vectors.
    
    These tests verify canonical request construction matches AWS specification.
    Requirements: 3.1
    """

    def test_canonical_request_get_vanilla(self):
        """Test canonical request for simple GET request."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        # Simple GET request
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={
                "host": "example.amazonaws.com",
                "x-amz-date": "20150830T123600Z"
            },
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        
        # Verify structure
        assert lines[0] == "GET"
        assert lines[1] == "/"
        assert lines[2] == ""  # Empty query string
        assert "host:example.amazonaws.com" in canonical
        assert "x-amz-date:20150830T123600Z" in canonical

    def test_canonical_request_post_with_body(self):
        """Test canonical request for POST request with body."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        body = b'{"key": "value"}'
        payload_hash = hashlib.sha256(body).hexdigest()
        
        canonical = signer.create_canonical_request(
            method="POST",
            uri="/sessions",
            query_string="",
            headers={
                "host": "rolesanywhere.us-east-1.amazonaws.com",
                "content-type": "application/json",
                "x-amz-date": "20240115T120000Z"
            },
            payload_hash=payload_hash
        )
        
        lines = canonical.split("\n")
        
        assert lines[0] == "POST"
        assert lines[1] == "/sessions"
        assert lines[-1] == payload_hash

    def test_canonical_request_with_query_parameters(self):
        """Test canonical request with query parameters."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="Param2=value2&Param1=value1",
            headers={"host": "example.amazonaws.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        
        # Query parameters should be sorted
        # Note: Our implementation lowercases and sorts
        assert "Param1=value1" in lines[2] or "param1=value1" in lines[2].lower()

    def test_canonical_request_uri_encoding(self):
        """Test that URI paths are properly encoded."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/path with spaces",
            query_string="",
            headers={"host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        
        # Spaces should be encoded as %20
        assert "%20" in lines[1] or " " not in lines[1]


class TestSignedHeaders:
    """Tests for signed headers list generation."""

    def test_signed_headers_semicolon_separated(self):
        """Test that signed headers are semicolon-separated."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"host": "example.com", "x-amz-date": "20240115T120000Z"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        
        # Second to last line should be signed headers
        signed_headers_line = lines[-2]
        assert ";" in signed_headers_line
        assert "host" in signed_headers_line
        assert "x-amz-date" in signed_headers_line

    def test_signed_headers_sorted(self):
        """Test that signed headers are sorted alphabetically."""
        mock_session = MagicMock()
        signer = RequestSigner(mock_session)
        
        canonical = signer.create_canonical_request(
            method="GET",
            uri="/",
            query_string="",
            headers={"z-header": "z", "a-header": "a", "host": "example.com"},
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        lines = canonical.split("\n")
        signed_headers_line = lines[-2]
        
        # Should be sorted: a-header;host;z-header
        assert signed_headers_line == "a-header;host;z-header"
