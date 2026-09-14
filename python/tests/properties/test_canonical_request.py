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
Property-based tests for canonical request format.

Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
Validates: Requirements 3.1
"""

import hashlib
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from yubira.request_signer import RequestSigner


# Strategy for HTTP methods
http_method_strategy = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])

# Strategy for URI path segments, including characters that require one or
# two URI-encoding passes and representative non-ASCII input.
path_segment_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~ %:ü",
    min_size=1,
    max_size=20,
)

# Strategy for URI paths
uri_path_strategy = st.lists(
    path_segment_strategy,
    min_size=0,
    max_size=5,
).map(lambda segments: "/" + "/".join(segments) if segments else "/")

# Strategy for header names (lowercase letters and hyphens)
header_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",), whitelist_characters="-"),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.startswith("-") and not s.endswith("-") and "--" not in s)

# Strategy for header values (printable ASCII, may have extra whitespace)
header_value_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S"), whitelist_characters=" "),
    min_size=1,
    max_size=50,
).filter(lambda s: s.strip())  # Must have non-whitespace content

# Strategy for headers dictionary
headers_strategy = st.dictionaries(
    keys=header_name_strategy,
    values=header_value_strategy,
    min_size=1,
    max_size=5,
)

# Strategy for payload hash (valid SHA-256 hex string)
payload_hash_strategy = st.binary(min_size=1, max_size=100).map(
    lambda b: hashlib.sha256(b).hexdigest()
)

# Strategy for already URL-encoded query parameters. Include percent escapes,
# ARN punctuation encodings, and encoded equals signs while excluding raw '&'.
query_key_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%",
    min_size=1,
    max_size=12,
)
query_value_strategy = st.one_of(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%",
        min_size=0,
        max_size=24,
    ),
    st.sampled_from(
        [
            "value%3Dwith%3Dequals",
            "arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FExample",
            "%C3%BCmlaut",
        ]
    ),
)
query_param_strategy = st.tuples(query_key_strategy, query_value_strategy)

query_string_strategy = st.lists(
    query_param_strategy,
    min_size=0,
    max_size=5,
).map(lambda params: "&".join(f"{key}={value}" for key, value in params))


def create_mock_signer() -> RequestSigner:
    """Create a RequestSigner with mocked PIV session."""
    mock_session = MagicMock()
    return RequestSigner(mock_session)


class TestCanonicalRequestFormat:
    """
    Property 2: Canonical Request Format
    
    For any valid combination of HTTP method, URI path, headers, and payload,
    the canonical request construction SHALL produce a string that:
    - Contains the method in uppercase on the first line
    - Contains the URI-encoded path on the second line
    - Contains sorted, lowercase header names with trimmed values
    - Ends with the SHA-256 hash of the payload
    
    Validates: Requirements 3.1
    """

    @given(
        method=http_method_strategy,
        uri=uri_path_strategy,
        query_string=query_string_strategy,
        headers=headers_strategy,
        payload_hash=payload_hash_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_request_method_uppercase_first_line(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
    ):
        """
        Property: The canonical request MUST contain the HTTP method in 
        uppercase on the first line.
        
        Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
        Validates: Requirements 3.1
        """
        signer = create_mock_signer()
        
        canonical_request = signer.create_canonical_request(
            method=method,
            uri=uri,
            query_string=query_string,
            headers=headers,
            payload_hash=payload_hash,
        )
        
        lines = canonical_request.split("\n")
        
        # Property: First line is the method in uppercase
        assert lines[0] == method.upper()

    @given(
        method=http_method_strategy,
        uri=uri_path_strategy,
        query_string=query_string_strategy,
        headers=headers_strategy,
        payload_hash=payload_hash_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_request_uri_on_second_line(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
    ):
        """
        Property: The canonical request MUST contain the URI-encoded path 
        on the second line.
        
        Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
        Validates: Requirements 3.1
        """
        signer = create_mock_signer()
        
        canonical_request = signer.create_canonical_request(
            method=method,
            uri=uri,
            query_string=query_string,
            headers=headers,
            payload_hash=payload_hash,
        )
        
        lines = canonical_request.split("\n")
        
        # Property: Second line is the URI path (starts with /)
        assert lines[1].startswith("/")
        # The URI should be properly encoded (no spaces, etc.)
        assert " " not in lines[1]

    @given(
        method=http_method_strategy,
        uri=uri_path_strategy,
        query_string=query_string_strategy,
        headers=headers_strategy,
        payload_hash=payload_hash_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_request_headers_sorted_lowercase(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
    ):
        """
        Property: The canonical request MUST contain sorted, lowercase 
        header names with trimmed values.
        
        Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
        Validates: Requirements 3.1
        """
        signer = create_mock_signer()
        
        canonical_request = signer.create_canonical_request(
            method=method,
            uri=uri,
            query_string=query_string,
            headers=headers,
            payload_hash=payload_hash,
        )
        
        lines = canonical_request.split("\n")
        
        # Find header lines (after method, uri, query string, before signed headers)
        # Format: method, uri, query, headers..., empty line after headers, signed_headers, payload_hash
        # Headers section starts at line 3 and ends with a line containing just header names
        
        # Extract header lines (lines that contain ':')
        header_lines = []
        for i, line in enumerate(lines):
            if i >= 3 and ":" in line:
                header_lines.append(line)
            elif i >= 3 and ":" not in line and header_lines:
                # We've passed the headers section
                break
        
        # Property: Header names must be lowercase
        header_names = []
        for header_line in header_lines:
            name, _ = header_line.split(":", 1)
            assert name == name.lower(), f"Header name '{name}' is not lowercase"
            header_names.append(name)
        
        # Property: Headers must be sorted alphabetically
        assert header_names == sorted(header_names), "Headers are not sorted"

    @given(
        method=http_method_strategy,
        uri=uri_path_strategy,
        query_string=query_string_strategy,
        headers=headers_strategy,
        payload_hash=payload_hash_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_request_ends_with_payload_hash(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
    ):
        """
        Property: The canonical request MUST end with the SHA-256 hash 
        of the payload.
        
        Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
        Validates: Requirements 3.1
        """
        signer = create_mock_signer()
        
        canonical_request = signer.create_canonical_request(
            method=method,
            uri=uri,
            query_string=query_string,
            headers=headers,
            payload_hash=payload_hash,
        )
        
        lines = canonical_request.split("\n")
        
        # Property: Last line is the payload hash
        assert lines[-1] == payload_hash

    @given(
        method=http_method_strategy,
        uri=uri_path_strategy,
        headers=headers_strategy,
        payload_hash=payload_hash_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_request_structure_has_six_parts(
        self,
        method: str,
        uri: str,
        headers: Dict[str, str],
        payload_hash: str,
    ):
        """
        Property: The canonical request MUST have the correct structure:
        method, uri, query, headers, signed_headers, payload_hash.
        
        Feature: yubikey-iam-roles-anywhere, Property 2: Canonical Request Format
        Validates: Requirements 3.1
        """
        signer = create_mock_signer()
        
        canonical_request = signer.create_canonical_request(
            method=method,
            uri=uri,
            query_string="",
            headers=headers,
            payload_hash=payload_hash,
        )
        
        lines = canonical_request.split("\n")
        
        # Minimum structure: method, uri, query, at least one header + newline, 
        # signed_headers, payload_hash
        # With N headers, we have: 3 + N + 1 (empty after headers) + 1 + 1 = N + 6 lines
        # But our format is: method, uri, query, headers (each with newline), signed_headers, hash
        # Actually: method\nuri\nquery\nheader1:val\n...\nheaderN:val\n\nsigned_headers\nhash
        
        # At minimum we need: method, uri, query_string, headers section, signed_headers, hash
        assert len(lines) >= 6, f"Expected at least 6 lines, got {len(lines)}"
        
        # First line is method
        assert lines[0] == method.upper()
        
        # Second line is URI
        assert lines[1].startswith("/")
        
        # Third line is query string (can be empty)
        # Lines 3 to -3 are headers (ending with newline)
        # Second to last is signed headers (semicolon-separated)
        # Last is payload hash
        assert lines[-1] == payload_hash
