"""RSA key-size validation for IAM Roles Anywhere signing."""

from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from yubikit.piv import KEY_TYPE

from yubira.request_signer import RequestSigner, SigningError


def rsa_certificate_with_size(key_size: int) -> MagicMock:
    """Return a certificate mock whose public key reports an RSA size."""
    public_key = MagicMock(spec=rsa.RSAPublicKey)
    public_key.key_size = key_size
    certificate = MagicMock()
    certificate.public_key.return_value = public_key
    return certificate


def test_rsa_2048_is_accepted_and_selected_for_signing() -> None:
    session = MagicMock()
    session.get_certificate.return_value = rsa_certificate_with_size(2048)
    session.sign.return_value = b"signature"
    signer = RequestSigner(session)

    assert signer.get_signature_algorithm() == "RSA-SHA256"
    assert signer.sign(b"string-to-sign") == b"signature"
    assert session.sign.call_args.args[1] == KEY_TYPE.RSA2048


@pytest.mark.parametrize("key_size", [1024, 3072, 4096])
def test_unsupported_rsa_sizes_fail_before_token_signing(key_size: int) -> None:
    session = MagicMock()
    session.get_certificate.return_value = rsa_certificate_with_size(key_size)
    signer = RequestSigner(session)

    with pytest.raises(SigningError, match=f"Unsupported RSA key size: {key_size}"):
        signer.get_signature_algorithm()

    session.sign.assert_not_called()
