"""Credential representation and debug-redaction regression tests."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock

from yubira.request_signer import RequestSigner
from yubira.roles_anywhere_client import AWSCredentials, RolesAnywhereClient


ACCESS_KEY = "synthetic-access-key-id"
SECRET_KEY = "synthetic-secret-access-key-value"
SESSION_TOKEN = "synthetic-session-token-value"
CERTIFICATE = "synthetic-base64-certificate"
AUTHORIZATION = "synthetic-signed-authorization"


def make_client() -> RolesAnywhereClient:
    return RolesAnywhereClient(
        trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/SECRET",
        profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/SECRET",
        role_arn="arn:aws:iam::123456789012:role/SecretRole",
    )


def test_credentials_repr_redacts_all_credential_values() -> None:
    credentials = AWSCredentials(
        access_key_id=ACCESS_KEY,
        secret_access_key=SECRET_KEY,
        session_token=SESSION_TOKEN,
        expiration=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    rendered = repr(credentials)
    assert ACCESS_KEY not in rendered
    assert SECRET_KEY not in rendered
    assert SESSION_TOKEN not in rendered
    assert "expiration=" in rendered


def test_request_debug_omits_replayable_material(capsys) -> None:
    client = make_client()
    signer = MagicMock(spec=RequestSigner)
    signer.create_canonical_request.return_value = (
        f"canonical:{CERTIFICATE}:{AUTHORIZATION}:{SECRET_KEY}"
    )
    signer.create_string_to_sign.return_value = f"string-to-sign:{SESSION_TOKEN}"
    headers = {
        "Host": "rolesanywhere.us-east-1.amazonaws.com",
        "Content-Type": "application/json",
        "X-Amz-Date": "20260101T000000Z",
        "X-Amz-X509": CERTIFICATE,
        "X-Amz-X509-Chain": "synthetic-intermediate-chain",
        "Authorization": AUTHORIZATION,
    }

    client._print_debug(
        "https://rolesanywhere.us-east-1.amazonaws.com/sessions?roleArn=SECRET",
        headers,
        b'{"durationSeconds":3600}',
        signer,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    rendered = capsys.readouterr().err
    for sensitive in (
        "roleArn=SECRET",
        CERTIFICATE,
        "synthetic-intermediate-chain",
        AUTHORIZATION,
        SECRET_KEY,
        SESSION_TOKEN,
        "canonical:",
        "string-to-sign:",
    ):
        assert sensitive not in rendered
    assert "?<redacted>" in rendered
    assert "X-Amz-X509: <redacted>" in rendered
    assert "X-Amz-X509-Chain: <redacted>" in rendered
    assert "Authorization: <redacted>" in rendered
    assert "Canonical request SHA-256:" in rendered
    assert "String-to-sign SHA-256:" in rendered


def test_response_debug_never_formats_headers_or_body(capsys) -> None:
    response = Mock()
    response.status_code = 201
    response.headers = {
        "x-amzn-requestid": "safe-request-id",
        "content-type": "application/json",
        "authorization": AUTHORIZATION,
    }
    response.text = (
        f'{{"accessKeyId":"{ACCESS_KEY}","secretAccessKey":"{SECRET_KEY}",'
        f'"sessionToken":"{SESSION_TOKEN}"}}'
    )

    RolesAnywhereClient._print_response_debug(response)

    rendered = capsys.readouterr().err
    assert "safe-request-id" in rendered
    assert "Body: <redacted>" in rendered
    assert AUTHORIZATION not in rendered
    assert ACCESS_KEY not in rendered
    assert SECRET_KEY not in rendered
    assert SESSION_TOKEN not in rendered
