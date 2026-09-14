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
"""Tests for security-sensitive CLI configuration validation."""

import pytest

from yubira.input_validation import ConfigurationError, validate_configuration


VALID = {
    "trust_anchor_arn": (
        "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/anchor-1"
    ),
    "profile_arn": "arn:aws:rolesanywhere:us-east-1:123456789012:profile/profile-1",
    "role_arn": "arn:aws:iam::210987654321:role/path/ExampleRole",
    "region": "us-east-1",
    "session_duration": 3600,
}


def validate(**changes):
    values = VALID | changes
    validate_configuration(**values)


def test_valid_configuration_allows_cross_account_role():
    validate()


def test_valid_govcloud_configuration():
    validate(
        trust_anchor_arn=(
            "arn:aws-us-gov:rolesanywhere:us-gov-west-1:123456789012:"
            "trust-anchor/anchor-1"
        ),
        profile_arn=(
            "arn:aws-us-gov:rolesanywhere:us-gov-west-1:123456789012:"
            "profile/profile-1"
        ),
        role_arn="arn:aws-us-gov:iam::210987654321:role/ExampleRole",
        region="us-gov-west-1",
    )


@pytest.mark.parametrize("duration", [899, 43_201])
def test_duration_outside_service_bounds_is_rejected(duration):
    with pytest.raises(ConfigurationError, match="between 900 and 43200"):
        validate(session_duration=duration)


@pytest.mark.parametrize("region", ["x/", "us-east-1.example.com", "US-EAST-1"])
def test_unsafe_region_syntax_is_rejected(region):
    with pytest.raises(ConfigurationError, match="region"):
        validate(region=region)


def test_roles_anywhere_region_must_match_cli_region():
    with pytest.raises(ConfigurationError, match="regions must match"):
        validate(region="us-west-2")


def test_trust_anchor_and_profile_accounts_must_match():
    with pytest.raises(ConfigurationError, match="accounts must match"):
        validate(
            profile_arn=(
                "arn:aws:rolesanywhere:us-east-1:999999999999:profile/profile-1"
            )
        )


def test_role_partition_must_match():
    with pytest.raises(ConfigurationError, match="partitions must match"):
        validate(role_arn="arn:aws-us-gov:iam::210987654321:role/ExampleRole")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("trust_anchor_arn", "not-an-arn", "complete ARN"),
        (
            "profile_arn",
            "arn:aws:iam:us-east-1:123456789012:profile/example",
            "rolesanywhere service",
        ),
        (
            "role_arn",
            "arn:aws:rolesanywhere::210987654321:role/ExampleRole",
            "iam service",
        ),
        (
            "trust_anchor_arn",
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/example",
            "invalid resource",
        ),
    ],
)
def test_wrong_arn_shapes_are_rejected(field, value, message):
    with pytest.raises(ConfigurationError, match=message):
        validate(**{field: value})
