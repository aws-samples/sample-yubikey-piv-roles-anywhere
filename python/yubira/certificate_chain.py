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
"""Optional intermediate-certificate chain loading and validation."""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


MAX_CHAIN_CERTIFICATES = 5
MAX_CHAIN_FILE_BYTES = 64 * 1024


class CertificateChainError(ValueError):
    """Raised when an optional certificate chain is unsafe or malformed."""


def validate_certificate_chain(
    leaf_der: bytes,
    chain_der: list[bytes] | tuple[bytes, ...],
) -> tuple[bytes, ...]:
    """Validate a leaf-issuer-first intermediate chain and return stable DER."""
    if not chain_der:
        raise CertificateChainError("certificate chain is empty")
    if len(chain_der) > MAX_CHAIN_CERTIFICATES:
        raise CertificateChainError("certificate chain exceeds five certificates")

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        chain = [x509.load_der_x509_certificate(item) for item in chain_der]
    except ValueError as exc:
        raise CertificateChainError("certificate chain contains invalid DER") from exc

    normalized = tuple(cert.public_bytes(Encoding.DER) for cert in chain)
    fingerprints = {leaf.public_bytes(Encoding.DER)}
    expected_issuer = leaf.issuer
    for cert, encoded in zip(chain, normalized):
        if encoded in fingerprints:
            raise CertificateChainError("certificate chain contains a duplicate certificate")
        if cert.subject != expected_issuer:
            raise CertificateChainError("certificate chain is not ordered from the leaf issuer")
        fingerprints.add(encoded)
        expected_issuer = cert.issuer

    return normalized


def load_certificate_chain(path: str, leaf_der: bytes) -> tuple[bytes, ...]:
    """Read a bounded PEM bundle and validate it against the leaf certificate."""
    chain_path = Path(path)
    try:
        size = chain_path.stat().st_size
    except OSError as exc:
        raise CertificateChainError("certificate chain file cannot be read") from exc
    if size > MAX_CHAIN_FILE_BYTES:
        raise CertificateChainError("certificate chain file exceeds 65536 bytes")

    try:
        pem_data = chain_path.read_bytes()
        if len(pem_data) > MAX_CHAIN_FILE_BYTES:
            raise CertificateChainError("certificate chain file exceeds 65536 bytes")
        certificates = x509.load_pem_x509_certificates(pem_data)
    except (OSError, ValueError) as exc:
        raise CertificateChainError("certificate chain file is not valid PEM") from exc

    return validate_certificate_chain(
        leaf_der,
        [cert.public_bytes(Encoding.DER) for cert in certificates],
    )


def encode_certificate_chain(chain_der: tuple[bytes, ...]) -> str:
    """Encode validated intermediates as comma-delimited base64 DER."""
    import base64

    return ",".join(base64.b64encode(item).decode("ascii") for item in chain_der)
