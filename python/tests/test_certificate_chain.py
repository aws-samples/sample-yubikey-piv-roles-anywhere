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
"""Tests for optional intermediate-certificate chain handling."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from yubira.certificate_chain import (
    CertificateChainError,
    load_certificate_chain,
    validate_certificate_chain,
)


def certificate(subject_name: str, issuer_name: str) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def test_loads_leaf_issuer_first_pem_bundle(tmp_path):
    leaf = certificate("leaf", "intermediate")
    intermediate = certificate("intermediate", "root")
    bundle = tmp_path / "chain.pem"
    bundle.write_bytes(intermediate.public_bytes(Encoding.PEM))

    chain = load_certificate_chain(str(bundle), leaf.public_bytes(Encoding.DER))

    assert chain == (intermediate.public_bytes(Encoding.DER),)


def test_rejects_wrong_chain_order():
    leaf = certificate("leaf", "intermediate")
    unrelated = certificate("other", "root")

    with pytest.raises(CertificateChainError, match="ordered"):
        validate_certificate_chain(
            leaf.public_bytes(Encoding.DER),
            [unrelated.public_bytes(Encoding.DER)],
        )


def test_rejects_duplicate_leaf():
    leaf = certificate("leaf", "leaf")
    leaf_der = leaf.public_bytes(Encoding.DER)

    with pytest.raises(CertificateChainError, match="duplicate"):
        validate_certificate_chain(leaf_der, [leaf_der])


def test_rejects_more_than_five_certificates():
    leaf = certificate("leaf", "issuer")

    with pytest.raises(CertificateChainError, match="exceeds five"):
        validate_certificate_chain(leaf.public_bytes(Encoding.DER), [b"x"] * 6)


def test_rejects_malformed_pem(tmp_path):
    bundle = tmp_path / "chain.pem"
    bundle.write_text("not a certificate")
    leaf = certificate("leaf", "issuer")

    with pytest.raises(CertificateChainError, match="valid PEM"):
        load_certificate_chain(str(bundle), leaf.public_bytes(Encoding.DER))


def test_encodes_comma_delimited_base64_der():
    from yubira.certificate_chain import encode_certificate_chain

    assert encode_certificate_chain((b"one", b"two")) == "b25l,dHdv"


def test_chain_header_is_emitted_and_signed():
    from yubira.request_signer import RequestSigner
    from yubira.roles_anywhere_client import RolesAnywhereClient

    leaf = certificate("leaf", "intermediate")
    intermediate = certificate("intermediate", "root")
    client = RolesAnywhereClient(
        trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/example",
        profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/example",
        role_arn="arn:aws:iam::123456789012:role/ExampleRole",
    )
    headers = client._build_headers(
        leaf.public_bytes(Encoding.DER),
        datetime.now(timezone.utc),
        2,
        (intermediate.public_bytes(Encoding.DER),),
    )
    _, signed_headers = RequestSigner(None)._create_canonical_headers(headers)

    assert headers["X-Amz-X509-Chain"]
    assert "x-amz-x509-chain" in signed_headers.split(";")
