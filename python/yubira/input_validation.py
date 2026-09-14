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
"""Validation for security-sensitive IAM Roles Anywhere CLI inputs."""

from dataclasses import dataclass
import re


class ConfigurationError(ValueError):
    """Raised when CLI configuration is unsafe or internally inconsistent."""


_REGION_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
_ROLE_RE = re.compile(r"^role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_SPECIAL_REGION_PREFIXES = (
    "cn-",
    "us-gov-",
    "us-iso-",
    "us-isob-",
    "eu-isoe-",
    "us-isof-",
)


@dataclass(frozen=True)
class _Arn:
    partition: str
    service: str
    region: str
    account: str
    resource: str


def _parse_arn(value: str, label: str) -> _Arn:
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        raise ConfigurationError(f"{label} must be a complete ARN")

    arn = _Arn(*parts[1:])
    if not _ACCOUNT_RE.fullmatch(arn.account):
        raise ConfigurationError(f"{label} must contain a 12-digit account ID")
    return arn


def _validate_region(region: str) -> None:
    if len(region) > 32 or not _REGION_RE.fullmatch(region):
        raise ConfigurationError("region has invalid syntax")


def _validate_partition_region(partition: str, region: str) -> None:
    if partition == "aws":
        if region.startswith(_SPECIAL_REGION_PREFIXES):
            raise ConfigurationError("region does not match ARN partition")
        return
    if partition == "aws-us-gov" and region.startswith("us-gov-"):
        return
    raise ConfigurationError("ARN partition is unsupported or inconsistent with region")


def validate_configuration(
    trust_anchor_arn: str,
    profile_arn: str,
    role_arn: str,
    region: str,
    session_duration: int,
) -> None:
    """Validate configuration before connecting to or signing with a YubiKey."""
    _validate_region(region)
    if not 900 <= session_duration <= 43_200:
        raise ConfigurationError("session duration must be between 900 and 43200 seconds")

    trust_anchor = _parse_arn(trust_anchor_arn, "trust anchor ARN")
    profile = _parse_arn(profile_arn, "profile ARN")
    role = _parse_arn(role_arn, "role ARN")

    if trust_anchor.service != "rolesanywhere":
        raise ConfigurationError("trust anchor ARN must use the rolesanywhere service")
    if profile.service != "rolesanywhere":
        raise ConfigurationError("profile ARN must use the rolesanywhere service")
    if role.service != "iam":
        raise ConfigurationError("role ARN must use the iam service")

    if trust_anchor.region != region or profile.region != region:
        raise ConfigurationError("Roles Anywhere ARN regions must match --region")
    if role.region:
        raise ConfigurationError("IAM role ARN region must be empty")

    if not trust_anchor.resource.startswith("trust-anchor/") or not _ID_RE.fullmatch(
        trust_anchor.resource.removeprefix("trust-anchor/")
    ):
        raise ConfigurationError("trust anchor ARN has an invalid resource")
    if not profile.resource.startswith("profile/") or not _ID_RE.fullmatch(
        profile.resource.removeprefix("profile/")
    ):
        raise ConfigurationError("profile ARN has an invalid resource")
    if not _ROLE_RE.fullmatch(role.resource) or "//" in role.resource:
        raise ConfigurationError("role ARN has an invalid resource")

    if trust_anchor.partition != profile.partition:
        raise ConfigurationError("trust anchor and profile partitions must match")
    if trust_anchor.account != profile.account:
        raise ConfigurationError("trust anchor and profile accounts must match")
    if role.partition != trust_anchor.partition:
        raise ConfigurationError("role and Roles Anywhere ARN partitions must match")

    _validate_partition_region(trust_anchor.partition, region)
