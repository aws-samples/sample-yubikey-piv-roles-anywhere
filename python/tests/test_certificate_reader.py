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
Unit tests for Certificate Reader.

Tests slot parsing, certificate info extraction, and error handling.
Requirements: 1.3, 1.4, 1.5
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from yubikit.piv import SLOT

from yubira.certificate_reader import (
    CertificateReader,
    CertificateInfo,
    CertificateNotFoundError,
    CertificateReadError,
    parse_slot,
    SLOT_MAP,
    ALL_CERTIFICATE_SLOTS,
)


def create_mock_certificate(
    key_type: str = "RSA",
    subject_cn: str = "Test Subject",
    issuer_cn: str = "Test Issuer",
    not_before: datetime = None,
    not_after: datetime = None,
) -> x509.Certificate:
    """Create a mock X.509 certificate for testing."""
    if not_before is None:
        not_before = datetime.utcnow() - timedelta(days=30)
    if not_after is None:
        not_after = datetime.utcnow() + timedelta(days=365)
    
    # Generate key based on type
    if key_type == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    else:  # EC
        private_key = ec.generate_private_key(ec.SECP256R1())
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )
    
    return cert


class TestSlotParsing:
    """Tests for slot parsing functionality. Requirements: 1.3, 1.4"""

    def test_parse_slot_9a_returns_authentication(self):
        """Test that '9a' parses to SLOT.AUTHENTICATION."""
        assert parse_slot("9a") == SLOT.AUTHENTICATION

    def test_parse_slot_9c_returns_signature(self):
        """Test that '9c' parses to SLOT.SIGNATURE."""
        assert parse_slot("9c") == SLOT.SIGNATURE

    def test_parse_slot_9d_returns_key_management(self):
        """Test that '9d' parses to SLOT.KEY_MANAGEMENT."""
        assert parse_slot("9d") == SLOT.KEY_MANAGEMENT

    def test_parse_slot_9e_returns_card_auth(self):
        """Test that '9e' parses to SLOT.CARD_AUTH."""
        assert parse_slot("9e") == SLOT.CARD_AUTH

    def test_parse_slot_case_insensitive(self):
        """Test that slot parsing is case insensitive."""
        assert parse_slot("9A") == SLOT.AUTHENTICATION
        assert parse_slot("9C") == SLOT.SIGNATURE

    def test_parse_slot_invalid_raises_value_error(self):
        """Test that invalid slot raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_slot("invalid")
        assert "Invalid slot" in str(exc_info.value)
        assert "9a" in str(exc_info.value)  # Should list valid slots

    def test_slot_map_contains_all_standard_slots(self):
        """Test that SLOT_MAP contains all standard PIV slots."""
        assert "9a" in SLOT_MAP
        assert "9c" in SLOT_MAP
        assert "9d" in SLOT_MAP
        assert "9e" in SLOT_MAP

    def test_all_certificate_slots_contains_expected_slots(self):
        """Test that ALL_CERTIFICATE_SLOTS contains expected slots."""
        assert SLOT.AUTHENTICATION in ALL_CERTIFICATE_SLOTS
        assert SLOT.SIGNATURE in ALL_CERTIFICATE_SLOTS
        assert SLOT.KEY_MANAGEMENT in ALL_CERTIFICATE_SLOTS
        assert SLOT.CARD_AUTH in ALL_CERTIFICATE_SLOTS


class TestCertificateInfoExtraction:
    """Tests for certificate info extraction. Requirements: 1.3"""

    def test_certificate_info_extracts_subject(self):
        """Test that CertificateInfo correctly extracts subject."""
        cert = create_mock_certificate(subject_cn="My Subject")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert "My Subject" in info.subject

    def test_certificate_info_extracts_issuer(self):
        """Test that CertificateInfo correctly extracts issuer."""
        cert = create_mock_certificate(issuer_cn="My Issuer")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert "My Issuer" in info.issuer

    def test_certificate_info_extracts_validity_dates(self):
        """Test that CertificateInfo correctly extracts validity dates."""
        not_before = datetime(2024, 1, 1, 0, 0, 0)
        not_after = datetime(2025, 12, 31, 23, 59, 59)
        cert = create_mock_certificate(not_before=not_before, not_after=not_after)
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.not_before.year == 2024
        assert info.not_after.year == 2025

    def test_certificate_info_detects_rsa_key_type(self):
        """Test that CertificateInfo correctly identifies RSA key type."""
        cert = create_mock_certificate(key_type="RSA")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.key_type == "RSA"

    def test_certificate_info_detects_ec_key_type(self):
        """Test that CertificateInfo correctly identifies EC key type."""
        cert = create_mock_certificate(key_type="EC")
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.key_type == "EC"

    def test_certificate_info_stores_slot(self):
        """Test that CertificateInfo stores the slot it was read from."""
        cert = create_mock_certificate()
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.SIGNATURE)
        
        assert info.slot == SLOT.SIGNATURE


class TestCertificateInfoExport:
    """Tests for certificate export functionality."""

    def test_to_der_returns_bytes(self):
        """Test that to_der returns DER-encoded bytes."""
        cert = create_mock_certificate()
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        der_bytes = info.to_der()
        assert isinstance(der_bytes, bytes)
        assert len(der_bytes) > 0

    def test_to_pem_returns_bytes(self):
        """Test that to_pem returns PEM-encoded bytes."""
        cert = create_mock_certificate()
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        pem_bytes = info.to_pem()
        assert isinstance(pem_bytes, bytes)
        assert b"-----BEGIN CERTIFICATE-----" in pem_bytes
        assert b"-----END CERTIFICATE-----" in pem_bytes

    def test_to_der_matches_original_certificate(self):
        """Test that to_der output matches original certificate encoding."""
        cert = create_mock_certificate()
        expected_der = cert.public_bytes(Encoding.DER)
        
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.to_der() == expected_der


class TestCertificateValidity:
    """Tests for certificate validity checking."""

    def test_is_expired_returns_true_for_expired_cert(self):
        """Test that is_expired returns True for expired certificate."""
        not_after = datetime.utcnow() - timedelta(days=1)
        cert = create_mock_certificate(not_after=not_after)
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.is_expired is True

    def test_is_expired_returns_false_for_valid_cert(self):
        """Test that is_expired returns False for valid certificate."""
        not_after = datetime.utcnow() + timedelta(days=365)
        cert = create_mock_certificate(not_after=not_after)
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.is_expired is False

    def test_is_not_yet_valid_returns_true_for_future_cert(self):
        """Test that is_not_yet_valid returns True for future certificate."""
        not_before = datetime.utcnow() + timedelta(days=30)
        cert = create_mock_certificate(not_before=not_before)
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert info.is_not_yet_valid is True


class TestErrorHandling:
    """Tests for error handling when no certificate in slot. Requirements: 1.5"""

    def test_read_certificate_raises_not_found_when_slot_empty(self):
        """Test that read_certificate raises CertificateNotFoundError for empty slot."""
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = None
        
        reader = CertificateReader(mock_session)
        
        with pytest.raises(CertificateNotFoundError) as exc_info:
            reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert "No certificate found" in str(exc_info.value)
        assert "9a" in str(exc_info.value)

    def test_read_certificate_raises_not_found_on_no_data_exception(self):
        """Test that read_certificate raises CertificateNotFoundError on 'no data' exception."""
        mock_session = MagicMock()
        mock_session.get_certificate.side_effect = Exception("no data available")
        
        reader = CertificateReader(mock_session)
        
        with pytest.raises(CertificateNotFoundError) as exc_info:
            reader.read_certificate(SLOT.SIGNATURE)
        
        assert "No certificate found" in str(exc_info.value)

    def test_read_certificate_raises_read_error_on_other_exception(self):
        """Test that read_certificate raises CertificateReadError on other exceptions."""
        mock_session = MagicMock()
        mock_session.get_certificate.side_effect = Exception("Connection lost")
        
        reader = CertificateReader(mock_session)
        
        with pytest.raises(CertificateReadError) as exc_info:
            reader.read_certificate(SLOT.AUTHENTICATION)
        
        assert "Failed to read certificate" in str(exc_info.value)


class TestListCertificates:
    """Tests for listing all certificates."""

    def test_list_certificates_returns_all_populated_slots(self):
        """Test that list_certificates returns certificates from all populated slots."""
        cert1 = create_mock_certificate(subject_cn="Cert 1")
        cert2 = create_mock_certificate(subject_cn="Cert 2")
        
        mock_session = MagicMock()
        
        def get_cert_side_effect(slot):
            if slot == SLOT.AUTHENTICATION:
                return cert1
            elif slot == SLOT.SIGNATURE:
                return cert2
            return None
        
        mock_session.get_certificate.side_effect = get_cert_side_effect
        
        reader = CertificateReader(mock_session)
        certs = reader.list_certificates()
        
        assert len(certs) == 2
        assert SLOT.AUTHENTICATION in certs
        assert SLOT.SIGNATURE in certs

    def test_list_certificates_returns_empty_dict_when_no_certs(self):
        """Test that list_certificates returns empty dict when no certificates."""
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = None
        
        reader = CertificateReader(mock_session)
        certs = reader.list_certificates()
        
        assert certs == {}

    def test_list_certificates_skips_slots_with_errors(self):
        """Test that list_certificates skips slots that raise errors."""
        cert = create_mock_certificate()
        mock_session = MagicMock()
        
        def get_cert_side_effect(slot):
            if slot == SLOT.AUTHENTICATION:
                return cert
            elif slot == SLOT.SIGNATURE:
                raise Exception("Connection error")
            return None
        
        mock_session.get_certificate.side_effect = get_cert_side_effect
        
        reader = CertificateReader(mock_session)
        certs = reader.list_certificates()
        
        assert len(certs) == 1
        assert SLOT.AUTHENTICATION in certs


class TestDefaultSlot:
    """Tests for default slot behavior. Requirements: 1.4"""

    def test_read_certificate_defaults_to_authentication_slot(self):
        """Test that read_certificate defaults to SLOT.AUTHENTICATION (9a)."""
        cert = create_mock_certificate()
        mock_session = MagicMock()
        mock_session.get_certificate.return_value = cert
        
        reader = CertificateReader(mock_session)
        info = reader.read_certificate()  # No slot specified
        
        # Verify get_certificate was called with AUTHENTICATION slot
        mock_session.get_certificate.assert_called_once_with(SLOT.AUTHENTICATION)
        assert info.slot == SLOT.AUTHENTICATION
