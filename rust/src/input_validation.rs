// MIT No Attribution
// Copyright 2026 AWS

//! Validation for security-sensitive IAM Roles Anywhere CLI inputs.

use crate::error::YubiraError;

struct Arn<'a> {
    partition: &'a str,
    service: &'a str,
    region: &'a str,
    account: &'a str,
    resource: &'a str,
}

fn invalid(message: impl Into<String>) -> YubiraError {
    YubiraError::InvalidConfiguration(message.into())
}

fn parse_arn<'a>(value: &'a str, label: &str) -> Result<Arn<'a>, YubiraError> {
    let parts: Vec<_> = value.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" {
        return Err(invalid(format!("{label} must be a complete ARN")));
    }
    if parts[4].len() != 12 || !parts[4].bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!(
            "{label} must contain a 12-digit account ID"
        )));
    }
    Ok(Arn {
        partition: parts[1],
        service: parts[2],
        region: parts[3],
        account: parts[4],
        resource: parts[5],
    })
}

fn validate_region(region: &str) -> Result<(), YubiraError> {
    let valid_chars = region
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let segments: Vec<_> = region.split('-').collect();
    let valid_shape = segments.len() >= 3
        && segments.iter().all(|segment| !segment.is_empty())
        && segments
            .last()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()));
    if region.len() > 32 || !valid_chars || !valid_shape {
        return Err(invalid("region has invalid syntax"));
    }
    Ok(())
}

fn validate_partition_region(partition: &str, region: &str) -> Result<(), YubiraError> {
    const SPECIAL_PREFIXES: [&str; 6] = [
        "cn-", "us-gov-", "us-iso-", "us-isob-", "eu-isoe-", "us-isof-",
    ];
    if partition == "aws" && !SPECIAL_PREFIXES.iter().any(|p| region.starts_with(p)) {
        return Ok(());
    }
    if partition == "aws-us-gov" && region.starts_with("us-gov-") {
        return Ok(());
    }
    Err(invalid(
        "ARN partition is unsupported or inconsistent with region",
    ))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(index, b)| b.is_ascii_alphanumeric() || (index > 0 && b == b'-'))
}

fn valid_role_resource(value: &str) -> bool {
    let Some(name) = value.strip_prefix("role/") else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 512
        && !name.contains("//")
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'/' | b'-')
        })
}

/// Validate configuration before connecting to or signing with a YubiKey.
pub fn validate_configuration(
    trust_anchor_arn: &str,
    profile_arn: &str,
    role_arn: &str,
    region: &str,
    session_duration: u32,
) -> Result<(), YubiraError> {
    validate_region(region)?;
    if !(900..=43_200).contains(&session_duration) {
        return Err(invalid(
            "session duration must be between 900 and 43200 seconds",
        ));
    }

    let trust_anchor = parse_arn(trust_anchor_arn, "trust anchor ARN")?;
    let profile = parse_arn(profile_arn, "profile ARN")?;
    let role = parse_arn(role_arn, "role ARN")?;

    if trust_anchor.service != "rolesanywhere" {
        return Err(invalid(
            "trust anchor ARN must use the rolesanywhere service",
        ));
    }
    if profile.service != "rolesanywhere" {
        return Err(invalid("profile ARN must use the rolesanywhere service"));
    }
    if role.service != "iam" {
        return Err(invalid("role ARN must use the iam service"));
    }
    if trust_anchor.region != region || profile.region != region {
        return Err(invalid("Roles Anywhere ARN regions must match --region"));
    }
    if !role.region.is_empty() {
        return Err(invalid("IAM role ARN region must be empty"));
    }

    let trust_id = trust_anchor
        .resource
        .strip_prefix("trust-anchor/")
        .filter(|id| valid_id(id))
        .ok_or_else(|| invalid("trust anchor ARN has an invalid resource"))?;
    let profile_id = profile
        .resource
        .strip_prefix("profile/")
        .filter(|id| valid_id(id))
        .ok_or_else(|| invalid("profile ARN has an invalid resource"))?;
    let _ = (trust_id, profile_id);
    if !valid_role_resource(role.resource) {
        return Err(invalid("role ARN has an invalid resource"));
    }

    if trust_anchor.partition != profile.partition {
        return Err(invalid("trust anchor and profile partitions must match"));
    }
    if trust_anchor.account != profile.account {
        return Err(invalid("trust anchor and profile accounts must match"));
    }
    if role.partition != trust_anchor.partition {
        return Err(invalid("role and Roles Anywhere ARN partitions must match"));
    }
    validate_partition_region(trust_anchor.partition, region)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUST: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/anchor-1";
    const PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/profile-1";
    const ROLE: &str = "arn:aws:iam::210987654321:role/path/ExampleRole";

    fn validate(
        trust: &str,
        profile: &str,
        role: &str,
        region: &str,
        duration: u32,
    ) -> Result<(), YubiraError> {
        validate_configuration(trust, profile, role, region, duration)
    }

    #[test]
    fn accepts_valid_cross_account_role() {
        validate(TRUST, PROFILE, ROLE, "us-east-1", 3600).unwrap();
    }

    #[test]
    fn accepts_valid_govcloud_configuration() {
        validate(
            "arn:aws-us-gov:rolesanywhere:us-gov-west-1:123456789012:trust-anchor/anchor-1",
            "arn:aws-us-gov:rolesanywhere:us-gov-west-1:123456789012:profile/profile-1",
            "arn:aws-us-gov:iam::210987654321:role/ExampleRole",
            "us-gov-west-1",
            900,
        )
        .unwrap();
    }

    #[test]
    fn rejects_unsafe_region_syntax() {
        for region in ["x/", "us-east-1.example.com", "US-EAST-1"] {
            assert!(validate(TRUST, PROFILE, ROLE, region, 3600).is_err());
        }
    }

    #[test]
    fn rejects_duration_outside_service_bounds() {
        assert!(validate(TRUST, PROFILE, ROLE, "us-east-1", 899).is_err());
        assert!(validate(TRUST, PROFILE, ROLE, "us-east-1", 43_201).is_err());
    }

    #[test]
    fn rejects_mismatched_regions_accounts_and_partitions() {
        assert!(validate(TRUST, PROFILE, ROLE, "us-west-2", 3600).is_err());
        assert!(validate(
            TRUST,
            "arn:aws:rolesanywhere:us-east-1:999999999999:profile/profile-1",
            ROLE,
            "us-east-1",
            3600,
        )
        .is_err());
        assert!(validate(
            TRUST,
            PROFILE,
            "arn:aws-us-gov:iam::210987654321:role/ExampleRole",
            "us-east-1",
            3600,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_arn_services_and_resources() {
        assert!(validate("not-an-arn", PROFILE, ROLE, "us-east-1", 3600).is_err());
        assert!(validate(
            TRUST,
            "arn:aws:iam:us-east-1:123456789012:profile/profile-1",
            ROLE,
            "us-east-1",
            3600,
        )
        .is_err());
        assert!(validate(
            TRUST,
            PROFILE,
            "arn:aws:rolesanywhere::210987654321:role/ExampleRole",
            "us-east-1",
            3600,
        )
        .is_err());
    }
}
