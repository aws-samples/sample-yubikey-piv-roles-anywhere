"""Shared IAM Roles Anywhere signing conformance vectors."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from yubira.request_signer import RequestSigner


VECTOR_FILE = (
    Path(__file__).resolve().parents[2]
    / "test-vectors"
    / "roles-anywhere-signing.json"
)
VECTOR_DOCUMENT = json.loads(VECTOR_FILE.read_text(encoding="utf-8"))
VECTORS = VECTOR_DOCUMENT["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_signing_vector(vector: dict) -> None:
    """Python must reproduce every language-neutral canonical byte string."""
    signer = RequestSigner(MagicMock())
    signer._cached_algorithm = {
        "rsa": "RSA-SHA256",
        "ec256": "ECDSA-SHA256",
        "ec384": "ECDSA-SHA256",
    }[vector["key_type"]]

    expected = vector["expected"]
    payload_hash = signer.hash_payload(vector["body"].encode("utf-8"))
    canonical_request = signer.create_canonical_request(
        method=vector["method"],
        uri=vector["uri"],
        query_string=vector["query_string"],
        headers=vector["headers"],
        payload_hash=payload_hash,
    )
    timestamp = datetime.fromisoformat(vector["timestamp"].replace("Z", "+00:00"))
    string_to_sign = signer.create_string_to_sign(
        timestamp=timestamp,
        region=vector["region"],
        canonical_request=canonical_request,
    )
    _, signed_headers = signer._create_canonical_headers(vector["headers"])

    assert signer._uri_encode_path(vector["uri"]) == expected["canonical_uri"]
    assert (
        signer._create_canonical_query_string(vector["query_string"])
        == expected["canonical_query"]
    )
    assert payload_hash == expected["payload_hash"]
    assert signed_headers == expected["signed_headers"]
    assert canonical_request == expected["canonical_request"]
    assert string_to_sign == expected["string_to_sign"]
