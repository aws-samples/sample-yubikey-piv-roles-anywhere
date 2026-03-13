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
Property-based tests for credential output schema conformance.

Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
Validates: Requirements 4.2, 5.1, 5.2
"""

import json
from datetime import datetime, timezone, timedelta

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from yubira.roles_anywhere_client import AWSCredentials


# Strategy for AWS access key IDs (AKIA... or ASIA... format)
access_key_id_strategy = st.sampled_from(["AKIA", "ASIA"]).flatmap(
    lambda prefix: st.text(
        alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        min_size=16,
        max_size=16,
    ).map(lambda suffix: prefix + suffix)
)

# Strategy for secret access keys (40 character base64-like string)
secret_access_key_strategy = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    min_size=40,
    max_size=40,
)

# Strategy for session tokens (variable length base64-like string)
session_token_strategy = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    min_size=100,
    max_size=500,
)

# Strategy for expiration timestamps (future UTC datetimes)
expiration_strategy = st.datetimes(
    min_value=datetime(2024, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
)


class TestCredentialOutputSchema:
    """
    Property 3: Credential Output Schema Conformance
    
    For any valid AWS credentials (access key ID, secret access key, 
    session token, expiration timestamp), the credential process output 
    SHALL produce valid JSON containing exactly the fields: Version 
    (integer 1), AccessKeyId, SecretAccessKey, SessionToken, and 
    Expiration (ISO8601 format).
    
    Validates: Requirements 4.2, 5.1, 5.2
    """

    @given(
        access_key_id=access_key_id_strategy,
        secret_access_key=secret_access_key_strategy,
        session_token=session_token_strategy,
        expiration=expiration_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_credential_output_is_valid_json(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: datetime,
    ):
        """
        Property: The credential process output MUST be valid JSON.
        
        Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
        Validates: Requirements 4.2, 5.1, 5.2
        """
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
        )
        
        output = credentials.to_credential_process_output()
        
        # Property: Output must be JSON-serializable
        json_str = json.dumps(output)
        
        # Property: JSON must be parseable back
        parsed = json.loads(json_str)
        assert parsed == output


    @given(
        access_key_id=access_key_id_strategy,
        secret_access_key=secret_access_key_strategy,
        session_token=session_token_strategy,
        expiration=expiration_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_credential_output_has_version_one(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: datetime,
    ):
        """
        Property: The credential process output MUST have Version field 
        equal to integer 1.
        
        Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
        Validates: Requirements 4.2, 5.1, 5.2
        """
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
        )
        
        output = credentials.to_credential_process_output()
        
        # Property: Version must be present and equal to 1
        assert "Version" in output
        assert output["Version"] == 1
        assert isinstance(output["Version"], int)

    @given(
        access_key_id=access_key_id_strategy,
        secret_access_key=secret_access_key_strategy,
        session_token=session_token_strategy,
        expiration=expiration_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_credential_output_has_required_fields(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: datetime,
    ):
        """
        Property: The credential process output MUST contain exactly the 
        fields: Version, AccessKeyId, SecretAccessKey, SessionToken, Expiration.
        
        Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
        Validates: Requirements 4.2, 5.1, 5.2
        """
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
        )
        
        output = credentials.to_credential_process_output()
        
        # Property: All required fields must be present
        required_fields = {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
        assert set(output.keys()) == required_fields

    @given(
        access_key_id=access_key_id_strategy,
        secret_access_key=secret_access_key_strategy,
        session_token=session_token_strategy,
        expiration=expiration_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_credential_output_preserves_credentials(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: datetime,
    ):
        """
        Property: The credential process output MUST preserve the original 
        credential values.
        
        Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
        Validates: Requirements 4.2, 5.1, 5.2
        """
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
        )
        
        output = credentials.to_credential_process_output()
        
        # Property: Credential values must match input
        assert output["AccessKeyId"] == access_key_id
        assert output["SecretAccessKey"] == secret_access_key
        assert output["SessionToken"] == session_token

    @given(
        access_key_id=access_key_id_strategy,
        secret_access_key=secret_access_key_strategy,
        session_token=session_token_strategy,
        expiration=expiration_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_credential_output_expiration_is_iso8601(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: datetime,
    ):
        """
        Property: The Expiration field MUST be in ISO8601 format with Z suffix.
        
        Feature: yubikey-iam-roles-anywhere, Property 3: Credential Output Schema Conformance
        Validates: Requirements 4.2, 5.1, 5.2
        """
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
        )
        
        output = credentials.to_credential_process_output()
        
        # Property: Expiration must be a string
        assert isinstance(output["Expiration"], str)
        
        # Property: Expiration must end with Z (UTC indicator)
        assert output["Expiration"].endswith("Z")
        
        # Property: Expiration must be parseable as ISO8601
        expiration_str = output["Expiration"]
        # Replace Z with +00:00 for parsing
        parsed = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
        
        # Property: Parsed expiration should match original (within microsecond precision)
        assert parsed.year == expiration.year
        assert parsed.month == expiration.month
        assert parsed.day == expiration.day
        assert parsed.hour == expiration.hour
        assert parsed.minute == expiration.minute
        assert parsed.second == expiration.second
