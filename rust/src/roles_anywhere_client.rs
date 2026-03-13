// MIT No Attribution
// Copyright 2026 AWS
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Roles Anywhere client for obtaining AWS credentials via IAM Roles Anywhere.

use base64::Engine;
use chrono::{DateTime, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yubikey::piv::SlotId;
use yubikey::YubiKey;

use crate::certificate_reader::CertificateInfo;
use crate::error::YubiraError;
use crate::request_signer;

const SERVICE: &str = "rolesanywhere";
const API_PATH: &str = "/sessions";

/// AWS temporary credentials returned by IAM Roles Anywhere.
#[derive(Debug, Clone)]
pub struct AWSCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
}

/// Credential process output format expected by AWS CLI.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessOutput {
    pub version: u32,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

impl AWSCredentials {
    /// Format credentials for AWS CLI credential_process.
    pub fn to_credential_process_output(&self) -> CredentialProcessOutput {
        CredentialProcessOutput {
            version: 1,
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            expiration: self.expiration.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}

/// CreateSession API response structures.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    credential_set: Vec<CredentialSetEntry>,
}

#[derive(Deserialize)]
struct CredentialSetEntry {
    credentials: CredentialFields,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialFields {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

/// Error response from the API.
#[derive(Deserialize)]
struct ErrorResponse {
    message: Option<String>,
    #[serde(alias = "Message")]
    message_alt: Option<String>,
}

/// Characters that must NOT be percent-encoded per RFC 3986.
/// Unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn build_query_string(
    trust_anchor_arn: &str,
    profile_arn: &str,
    role_arn: &str,
) -> String {
    let encode = |s: &str| utf8_percent_encode(s, QUERY_ENCODE_SET).to_string();
    format!(
        "profileArn={}&roleArn={}&trustAnchorArn={}",
        encode(profile_arn),
        encode(role_arn),
        encode(trust_anchor_arn),
    )
}

fn build_headers(
    host: &str,
    cert_der: &[u8],
    timestamp: &DateTime<Utc>,
    content_length: usize,
) -> BTreeMap<String, String> {
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
    let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();

    let mut headers = BTreeMap::new();
    headers.insert("content-length".to_string(), content_length.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("host".to_string(), host.to_string());
    headers.insert("x-amz-date".to_string(), amz_date);
    headers.insert("x-amz-x509".to_string(), cert_b64);
    headers
}

/// Call CreateSession API with signed request.
#[allow(clippy::too_many_arguments)]
pub fn create_session(
    yubikey: &mut YubiKey,
    slot: SlotId,
    cert_info: &CertificateInfo,
    trust_anchor_arn: &str,
    profile_arn: &str,
    role_arn: &str,
    region: &str,
    session_duration: u32,
    debug: bool,
) -> Result<AWSCredentials, YubiraError> {
    let timestamp = Utc::now();
    let host = format!("{SERVICE}.{region}.amazonaws.com");
    let endpoint = format!("https://{host}");

    // Build request body
    let body = format!("{{\"durationSeconds\":{session_duration}}}");
    let body_bytes = body.as_bytes();

    // Build query string
    let query_string = build_query_string(trust_anchor_arn, profile_arn, role_arn);

    // Build headers (lowercase keys, sorted via BTreeMap)
    let headers = build_headers(&host, cert_info.to_der(), &timestamp, body_bytes.len());

    // Compute payload hash
    let payload_hash = request_signer::hash_payload(body_bytes);

    // Create canonical request
    let canonical_request = request_signer::create_canonical_request(
        "POST",
        API_PATH,
        &query_string,
        &headers,
        &payload_hash,
    );

    // Create string to sign
    let string_to_sign = request_signer::create_string_to_sign(
        cert_info.key_type,
        &timestamp,
        region,
        &canonical_request,
    );

    // Sign with YubiKey
    let signature = request_signer::sign(
        yubikey,
        slot,
        cert_info.key_type,
        string_to_sign.as_bytes(),
    )?;

    // Build Authorization header
    let signed_headers = request_signer::get_signed_headers(&headers);
    let authorization = request_signer::build_authorization_header(
        cert_info.key_type,
        &cert_info.serial_number,
        &timestamp,
        region,
        &signed_headers,
        &signature,
    );

    // Build full URL
    let url = format!("{endpoint}{API_PATH}?{query_string}");

    // Debug output
    if debug {
        print_debug(&url, &headers, &authorization, body_bytes, &canonical_request, &string_to_sign, &timestamp);
    }

    // Send HTTP request
    let response = ureq::post(&url)
        .set("Authorization", &authorization)
        .set("Content-Type", "application/json")
        .set("Host", &host)
        .set("X-Amz-Date", &timestamp.format("%Y%m%dT%H%M%SZ").to_string())
        .set("X-Amz-X509", headers.get("x-amz-x509").unwrap())
        .set("Content-Length", &body_bytes.len().to_string())
        .timeout(std::time::Duration::from_secs(30))
        .send_bytes(body_bytes);

    match response {
        Ok(resp) => {
            let status = resp.status();
            let resp_body = resp.into_string().map_err(|e| {
                YubiraError::Api(format!("Failed to read response: {e}"))
            })?;

            if debug {
                eprintln!("\n=== RESPONSE ===");
                eprintln!("Status: {status}");
                eprintln!("Body: {resp_body}");
                eprintln!("================\n");
            }

            if status != 200 && status != 201 {
                let err: ErrorResponse = serde_json::from_str(&resp_body).unwrap_or(ErrorResponse {
                    message: Some("Unknown error".to_string()),
                    message_alt: None,
                });
                let msg = err.message.or(err.message_alt).unwrap_or_else(|| "Unknown error".to_string());
                return Err(YubiraError::Api(msg));
            }

            parse_response(&resp_body)
        }
        Err(ureq::Error::Transport(e)) => {
            Err(YubiraError::Network(e.to_string()))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let resp_body = resp.into_string().unwrap_or_default();
            if debug {
                eprintln!("\n=== RESPONSE ===");
                eprintln!("Status: {status}");
                eprintln!("Body: {resp_body}");
                eprintln!("================\n");
            }
            let err: ErrorResponse = serde_json::from_str(&resp_body).unwrap_or(ErrorResponse {
                message: Some("Unknown error".to_string()),
                message_alt: None,
            });
            let msg = err.message.or(err.message_alt).unwrap_or_else(|| "Unknown error".to_string());
            Err(YubiraError::Api(msg))
        }
    }
}

fn parse_response(body: &str) -> Result<AWSCredentials, YubiraError> {
    let resp: CreateSessionResponse = serde_json::from_str(body)
        .map_err(|e| YubiraError::Api(format!("Invalid JSON response: {e}")))?;

    let entry = resp.credential_set.first().ok_or_else(|| {
        YubiraError::Api("No credentials returned in response".to_string())
    })?;

    let creds = &entry.credentials;

    let expiration = DateTime::parse_from_rfc3339(&creds.expiration.replace('Z', "+00:00"))
        .map_err(|e| YubiraError::Api(format!("Invalid expiration format: {e}")))?
        .with_timezone(&Utc);

    Ok(AWSCredentials {
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.clone(),
        session_token: creds.session_token.clone(),
        expiration,
    })
}

fn print_debug(
    url: &str,
    headers: &BTreeMap<String, String>,
    authorization: &str,
    body: &[u8],
    canonical_request: &str,
    string_to_sign: &str,
    timestamp: &DateTime<Utc>,
) {
    eprintln!("\n=== DEBUG: REQUEST DETAILS ===");
    eprintln!("URL: {url}");
    eprintln!("Method: POST");
    eprintln!("Timestamp: {}", timestamp.to_rfc3339());
    eprintln!("\n--- Headers ---");
    eprintln!("Authorization: {authorization}");
    for (name, value) in headers {
        if name == "x-amz-x509" {
            let truncated = if value.len() > 70 {
                format!("{}...{}", &value[..50], &value[value.len() - 20..])
            } else {
                value.clone()
            };
            eprintln!("{name}: {truncated}");
        } else {
            eprintln!("{name}: {value}");
        }
    }
    eprintln!("\n--- Body ---");
    eprintln!("{}", String::from_utf8_lossy(body));
    eprintln!("\n--- Canonical Request ---");
    eprintln!("{canonical_request}");
    eprintln!("\n--- String to Sign ---");
    eprintln!("{string_to_sign}");
    eprintln!("==============================\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_process_output_format() {
        let creds = AWSCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(), // nosemgrep
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // nosemgrep
            session_token: "FwoGZXIvYXdzEBYaD".into(),
            expiration: DateTime::parse_from_rfc3339("2026-03-12T12:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
        };

        let output = creds.to_credential_process_output();
        assert_eq!(output.version, 1);
        assert_eq!(output.access_key_id, "AKIAIOSFODNN7EXAMPLE"); // nosemgrep
        assert_eq!(output.secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); // nosemgrep
        assert_eq!(output.session_token, "FwoGZXIvYXdzEBYaD");
        assert_eq!(output.expiration, "2026-03-12T12:00:00Z");
    }

    #[test]
    fn test_credential_process_output_serializes_to_json() {
        let creds = AWSCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(), // nosemgrep
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // nosemgrep
            session_token: "token".into(),
            expiration: DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
        };

        let output = creds.to_credential_process_output();
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["Version"], 1);
        assert_eq!(parsed["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE"); // nosemgrep
        assert_eq!(parsed["SecretAccessKey"], "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); // nosemgrep
        assert_eq!(parsed["SessionToken"], "token");
        assert_eq!(parsed["Expiration"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_build_query_string_contains_all_arns() {
        let qs = build_query_string(
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "arn:aws:iam::123456789012:role/TestRole",
        );

        assert!(qs.contains("profileArn="));
        assert!(qs.contains("roleArn="));
        assert!(qs.contains("trustAnchorArn="));
    }

    #[test]
    fn test_build_query_string_sorted_order() {
        let qs = build_query_string("trust", "profile", "role");
        // Parameters should be in order: profileArn, roleArn, trustAnchorArn
        let profile_pos = qs.find("profileArn").unwrap();
        let role_pos = qs.find("roleArn").unwrap();
        let trust_pos = qs.find("trustAnchorArn").unwrap();
        assert!(profile_pos < role_pos);
        assert!(role_pos < trust_pos);
    }

    #[test]
    fn test_build_query_string_encodes_special_chars() {
        let qs = build_query_string(
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc",
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def",
            "arn:aws:iam::123456789012:role/TestRole",
        );
        // Colons and slashes should be percent-encoded
        assert!(qs.contains("%3A") || qs.contains("%3a"));
        assert!(qs.contains("%2F") || qs.contains("%2f"));
        // Hyphens are unreserved per RFC 3986 and must NOT be encoded
        assert!(!qs.contains("%2D"), "hyphens should not be percent-encoded");
        assert!(qs.contains("us-east-1"));
    }

    #[test]
    fn test_build_headers_has_required_keys() {
        let ts = Utc::now();
        let headers = build_headers("rolesanywhere.us-east-1.amazonaws.com", b"certdata", &ts, 42);

        assert!(headers.contains_key("content-length"));
        assert!(headers.contains_key("content-type"));
        assert!(headers.contains_key("host"));
        assert!(headers.contains_key("x-amz-date"));
        assert!(headers.contains_key("x-amz-x509"));
    }

    #[test]
    fn test_build_headers_content_length() {
        let ts = Utc::now();
        let headers = build_headers("host.example.com", b"cert", &ts, 99);
        assert_eq!(headers["content-length"], "99");
    }

    #[test]
    fn test_build_headers_content_type() {
        let ts = Utc::now();
        let headers = build_headers("host.example.com", b"cert", &ts, 0);
        assert_eq!(headers["content-type"], "application/json");
    }

    #[test]
    fn test_build_headers_host() {
        let ts = Utc::now();
        let headers = build_headers("rolesanywhere.us-east-1.amazonaws.com", b"cert", &ts, 0);
        assert_eq!(headers["host"], "rolesanywhere.us-east-1.amazonaws.com");
    }

    #[test]
    fn test_build_headers_x509_is_base64() {
        let ts = Utc::now();
        let cert_bytes = b"test certificate data";
        let headers = build_headers("host", cert_bytes, &ts, 0);
        let x509_val = &headers["x-amz-x509"];
        // Should be valid base64
        assert!(base64::engine::general_purpose::STANDARD.decode(x509_val).is_ok());
    }

    #[test]
    fn test_build_headers_amz_date_format() {
        let ts = DateTime::parse_from_rfc3339("2026-03-12T10:30:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let headers = build_headers("host", b"cert", &ts, 0);
        assert_eq!(headers["x-amz-date"], "20260312T103000Z");
    }

    #[test]
    fn test_parse_response_valid() {
        // nosemgrep: aws-access-token, generic-api-key
        let body = r#"{
            "credentialSet": [{
                "credentials": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "sessionToken": "FwoGZXIvYXdzEBYaD",
                    "expiration": "2026-03-12T13:00:00Z"
                }
            }]
        }"#;

        let creds = parse_response(body).unwrap();
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE"); // nosemgrep
        assert_eq!(creds.secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); // nosemgrep
        assert_eq!(creds.session_token, "FwoGZXIvYXdzEBYaD");
    }

    #[test]
    fn test_parse_response_empty_credential_set() {
        let body = r#"{"credentialSet": []}"#;
        let err = parse_response(body).unwrap_err();
        match err {
            YubiraError::Api(msg) => assert!(msg.contains("No credentials")),
            _ => panic!("Expected Api error"),
        }
    }

    #[test]
    fn test_parse_response_invalid_json() {
        let err = parse_response("not json").unwrap_err();
        match err {
            YubiraError::Api(msg) => assert!(msg.contains("Invalid JSON")),
            _ => panic!("Expected Api error"),
        }
    }

    #[test]
    fn test_parse_response_invalid_expiration() {
        // nosemgrep: aws-access-token, generic-api-key
        let body = r#"{
            "credentialSet": [{
                "credentials": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "sessionToken": "token",
                    "expiration": "not-a-date"
                }
            }]
        }"#;
        let err = parse_response(body).unwrap_err();
        match err {
            YubiraError::Api(msg) => assert!(msg.contains("expiration")),
            _ => panic!("Expected Api error"),
        }
    }
}
