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
"""Certificate reader module for reading X.509 certificates from YubiKey PIV slots."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from yubikit.piv import PivSession, SLOT


class CertificateNotFoundError(Exception):
    """Raised when no certificate exists in the specified slot."""
    pass


class CertificateReadError(Exception):
    """Raised when reading a certificate fails."""
    pass


# Map of slot identifiers to SLOT enum values
SLOT_MAP: Dict[str, SLOT] = {
    "9a": SLOT.AUTHENTICATION,
    "9c": SLOT.SIGNATURE,
    "9d": SLOT.KEY_MANAGEMENT,
    "9e": SLOT.CARD_AUTH,
}

# All PIV slots that can contain certificates
ALL_CERTIFICATE_SLOTS = [
    SLOT.AUTHENTICATION,
    SLOT.SIGNATURE,
    SLOT.KEY_MANAGEMENT,
    SLOT.CARD_AUTH,
]


def parse_slot(slot_str: str) -> SLOT:
    """
    Parse a slot string identifier to a SLOT enum value.
    
    Args:
        slot_str: Slot identifier (e.g., "9a", "9c", "9d", "9e")
        
    Returns:
        Corresponding SLOT enum value.
        
    Raises:
        ValueError: If the slot identifier is not recognized.
    """
    slot_lower = slot_str.lower()
    if slot_lower not in SLOT_MAP:
        valid_slots = ", ".join(SLOT_MAP.keys())
        raise ValueError(f"Invalid slot '{slot_str}'. Valid slots are: {valid_slots}")
    return SLOT_MAP[slot_lower]


@dataclass
class CertificateInfo:
    """Information about a certificate stored in a YubiKey PIV slot."""
    
    certificate: x509.Certificate
    slot: SLOT
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    key_type: str  # "RSA" or "EC"
    
    def to_der(self) -> bytes:
        """Export certificate as DER-encoded bytes."""
        return self.certificate.public_bytes(Encoding.DER)
    
    def to_pem(self) -> bytes:
        """Export certificate as PEM-encoded bytes."""
        return self.certificate.public_bytes(Encoding.PEM)
    
    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        return datetime.now(timezone.utc).replace(tzinfo=None) > self.not_after
    
    @property
    def is_not_yet_valid(self) -> bool:
        """Check if the certificate is not yet valid."""
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.not_before


class CertificateReader:
    """
    Reads X.509 certificates from YubiKey PIV slots.
    
    Provides methods to read individual certificates or list all certificates
    stored in the YubiKey's PIV slots.
    """
    
    def __init__(self, session: PivSession):
        """
        Initialize the certificate reader.
        
        Args:
            session: An active PIV session from a connected YubiKey.
        """
        self._session = session
    
    def read_certificate(self, slot: SLOT = SLOT.AUTHENTICATION) -> CertificateInfo:
        """
        Read certificate from specified PIV slot.
        
        Args:
            slot: PIV slot to read from. Defaults to SLOT.AUTHENTICATION (9a).
            
        Returns:
            CertificateInfo containing the certificate and metadata.
            
        Raises:
            CertificateNotFoundError: If no certificate exists in the slot.
            CertificateReadError: If reading the certificate fails.
        """
        try:
            cert = self._session.get_certificate(slot)
        except Exception as e:
            error_msg = str(e).lower()
            if "no data" in error_msg or "not found" in error_msg or "no certificate" in error_msg:
                slot_name = self._get_slot_name(slot)
                raise CertificateNotFoundError(
                    f"No certificate found in slot {slot_name}."
                ) from e
            raise CertificateReadError(
                f"Failed to read certificate from slot: {e}"
            ) from e
        
        if cert is None:
            slot_name = self._get_slot_name(slot)
            raise CertificateNotFoundError(
                f"No certificate found in slot {slot_name}."
            )
        
        return self._create_certificate_info(cert, slot)
    
    def list_certificates(self) -> Dict[SLOT, CertificateInfo]:
        """
        List all certificates in PIV slots.
        
        Returns:
            Dictionary mapping SLOT to CertificateInfo for each slot
            that contains a certificate. Empty slots are not included.
        """
        certificates = {}
        
        for slot in ALL_CERTIFICATE_SLOTS:
            try:
                cert_info = self.read_certificate(slot)
                certificates[slot] = cert_info
            except CertificateNotFoundError:
                # Slot is empty, skip it
                continue
            except CertificateReadError:
                # Error reading slot, skip it
                continue
        
        return certificates
    
    def _create_certificate_info(self, cert: x509.Certificate, slot: SLOT) -> CertificateInfo:
        """Create a CertificateInfo object from a certificate."""
        # Determine key type
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
        else:
            key_type = "Unknown"
        
        return CertificateInfo(
            certificate=cert,
            slot=slot,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.replace(tzinfo=None),
            not_after=cert.not_valid_after_utc.replace(tzinfo=None),
            key_type=key_type,
        )
    
    @staticmethod
    def _get_slot_name(slot: SLOT) -> str:
        """Get a human-readable name for a slot."""
        slot_names = {
            SLOT.AUTHENTICATION: "9a (Authentication)",
            SLOT.SIGNATURE: "9c (Digital Signature)",
            SLOT.KEY_MANAGEMENT: "9d (Key Management)",
            SLOT.CARD_AUTH: "9e (Card Authentication)",
        }
        return slot_names.get(slot, str(slot))
