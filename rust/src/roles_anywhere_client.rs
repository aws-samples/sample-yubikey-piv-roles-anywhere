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
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};
use yubikey::piv::SlotId;
use yubikey::YubiKey;

use crate::certificate_reader::CertificateInfo;
use crate::error::YubiraError;
use crate::request_signer;

const SERVICE: &str = "rolesanywhere";
const API_PATH: &str = "/sessions";

/// AWS temporary credentials returned by IAM Roles Anywhere.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AWSCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    #[zeroize(skip)]
    pub expiration: DateTime<Utc>,
}

impl fmt::Debug for AWSCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AWSCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Borrowed credential process output expected by AWS CLI.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessOutput<'a> {
    pub version: u32,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: &'a str,
    pub expiration: String,
}

impl AWSCredentials {
    /// Format credentials for AWS CLI credential_process without cloning secrets.
    pub fn to_credential_process_output(&self) -> CredentialProcessOutput<'_> {
        CredentialProcessOutput {
            version: 1,
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            session_token: &self.session_token,
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
#[serde(rename_all = "camelCase")]
struct CredentialSetEntry {
    credentials: CredentialFields,
    role_arn: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
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

fn required_header<'a>(
    headers: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, YubiraError> {
    headers
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| YubiraError::Api(format!("Missing required request header: {name}")))
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
    certificate_chain_der: Option<&[Vec<u8>]>,
    debug: bool,
) -> Result<AWSCredentials, YubiraError> {
    let timestamp = Utc::now();
    crate::input_validation::validate_configuration(
        trust_anchor_arn,
        profile_arn,
        role_arn,
        region,
        session_duration,
    )?;
    let host = format!("{SERVICE}.{region}.amazonaws.com");
    let endpoint = format!("https://{host}");

    // Build request body
    let body = format!("{{\"durationSeconds\":{session_duration}}}");
    let body_bytes = body.as_bytes();

    // Build query string
    let query_string = build_query_string(trust_anchor_arn, profile_arn, role_arn);

    // Build headers (lowercase keys, sorted via BTreeMap)
    let mut headers = build_headers(&host, cert_info.to_der(), &timestamp, body_bytes.len());
    if let Some(chain_der) = certificate_chain_der {
        crate::certificate_chain::validate_certificate_chain(cert_info.to_der(), chain_der)?;
        headers.insert(
            "x-amz-x509-chain".to_string(),
            crate::certificate_chain::encode_certificate_chain(chain_der),
        );
    }
    let x509_header = required_header(&headers, "x-amz-x509")?;

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
        print_debug(
            &url,
            &headers,
            body_bytes,
            &canonical_request,
            &string_to_sign,
            &timestamp,
        );
    }

    // Send HTTP request
    let request = ureq::post(&url)
        .set("Authorization", &authorization)
        .set("Content-Type", "application/json")
        .set("Host", &host)
        .set("X-Amz-Date", &timestamp.format("%Y%m%dT%H%M%SZ").to_string())
        .set("X-Amz-X509", x509_header)
        .set("Content-Length", &body_bytes.len().to_string())
        .timeout(std::time::Duration::from_secs(30));
    let request = match headers.get("x-amz-x509-chain") {
        Some(chain_header) => request.set("X-Amz-X509-Chain", chain_header),
        None => request,
    };
    let response = request.send_bytes(body_bytes);

    match response {
        Ok(resp) => {
            let status = resp.status();
            let mut resp_body = resp.into_string().map_err(|e| {
                YubiraError::Api(format!("Failed to read response: {e}"))
            })?;

            if debug {
                print_response_debug(status);
            }

            if status != 200 && status != 201 {
                let err: ErrorResponse = serde_json::from_str(&resp_body).unwrap_or(ErrorResponse {
                    message: Some("Unknown error".to_string()),
                    message_alt: None,
                });
                let msg = err.message.or(err.message_alt).unwrap_or_else(|| "Unknown error".to_string());
                resp_body.zeroize();
                return Err(YubiraError::Api(msg));
            }

            let credentials = parse_response(&resp_body, role_arn);
            resp_body.zeroize();
            credentials
        }
        Err(ureq::Error::Transport(e)) => {
            Err(YubiraError::Network(e.to_string()))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let mut resp_body = resp.into_string().unwrap_or_default();
            if debug {
                print_response_debug(status);
            }
            let err: ErrorResponse = serde_json::from_str(&resp_body).unwrap_or(ErrorResponse {
                message: Some("Unknown error".to_string()),
                message_alt: None,
            });
            let msg = err.message.or(err.message_alt).unwrap_or_else(|| "Unknown error".to_string());
            resp_body.zeroize();
            Err(YubiraError::Api(msg))
        }
    }
}

fn parse_response(body: &str, expected_role_arn: &str) -> Result<AWSCredentials, YubiraError> {
    let resp: CreateSessionResponse = serde_json::from_str(body)
        .map_err(|e| YubiraError::Api(format!("Invalid JSON response: {e}")))?;

    let entry = resp.credential_set.into_iter().next().ok_or_else(|| {
        YubiraError::Api("No credentials returned in response".to_string())
    })?;
    if entry.role_arn != expected_role_arn {
        return Err(YubiraError::Api(
            "Returned role does not match requested role".to_string(),
        ));
    }
    let mut creds = entry.credentials;

    let expiration = DateTime::parse_from_rfc3339(&creds.expiration.replace('Z', "+00:00"))
        .map_err(|e| YubiraError::Api(format!("Invalid expiration format: {e}")))?
        .with_timezone(&Utc);

    Ok(AWSCredentials {
        access_key_id: std::mem::take(&mut creds.access_key_id),
        secret_access_key: std::mem::take(&mut creds.secret_access_key),
        session_token: std::mem::take(&mut creds.session_token),
        expiration,
    })
}

fn format_debug_request(
    url: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    canonical_request: &str,
    string_to_sign: &str,
    timestamp: &DateTime<Utc>,
) -> String {
    let base_url = url.split_once('?').map_or(url, |(base, _)| base);
    let mut output = format!(
        "\n=== DEBUG: REDACTED REQUEST DETAILS ===\n\
         URL: {base_url}?<redacted>\n\
         Method: POST\n\
         Timestamp: {}\n\n--- Headers ---\n",
        timestamp.to_rfc3339()
    );
    for (name, value) in headers {
        match name.as_str() {
            "host" | "content-type" | "x-amz-date" | "content-length" => {
                output.push_str(&format!("{name}: {value}\n"));
            }
            _ => output.push_str(&format!("{name}: <redacted>\n")),
        }
    }
    output.push_str(&format!(
        "Payload SHA-256: {}\n\
         Canonical request SHA-256: {}\n\
         String-to-sign SHA-256: {}\n\
         Sensitive request fields and response bodies are omitted.\n\
         =======================================\n",
        request_signer::hash_payload(body),
        request_signer::hash_payload(canonical_request.as_bytes()),
        request_signer::hash_payload(string_to_sign.as_bytes()),
    ));
    output
}

fn print_debug(
    url: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    canonical_request: &str,
    string_to_sign: &str,
    timestamp: &DateTime<Utc>,
) {
    eprintln!(
        "{}",
        format_debug_request(
            url,
            headers,
            body,
            canonical_request,
            string_to_sign,
            timestamp,
        )
    );
}

fn format_debug_response(status: u16) -> String {
    format!(
        "\n=== DEBUG: REDACTED RESPONSE ===\n\
         Status: {status}\n\
         Body: <redacted>\n\
         =================================\n"
    )
}

fn print_response_debug(status: u16) {
    eprintln!("{}", format_debug_response(status));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_process_output_format() {
        let creds = AWSCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(), // nosemgrep; gitleaks:allow -- AWS documentation fixture
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // nosemgrep; gitleaks:allow -- AWS documentation fixture
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
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(), // nosemgrep; gitleaks:allow -- AWS documentation fixture
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // nosemgrep; gitleaks:allow -- AWS documentation fixture
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
    fn test_required_header_returns_value() {
        let mut headers = BTreeMap::new();
        headers.insert("x-amz-x509".to_string(), "certificate".to_string());

        assert_eq!(required_header(&headers, "x-amz-x509").unwrap(), "certificate");
    }

    #[test]
    fn test_required_header_missing_returns_error() {
        let headers = BTreeMap::new();

        let err = required_header(&headers, "x-amz-x509").unwrap_err();
        match err {
            YubiraError::Api(msg) => assert_eq!(
                msg,
                "Missing required request header: x-amz-x509"
            ),
            _ => panic!("Expected Api error"),
        }
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
    fn test_chain_header_is_in_signed_headers() {
        let ts = Utc::now();
        let mut headers = build_headers("host", b"cert", &ts, 0);
        headers.insert("x-amz-x509-chain".into(), "b25l,dHdv".into());

        let signed = request_signer::get_signed_headers(&headers);
        assert!(signed.split(';').any(|name| name == "x-amz-x509-chain"));
    }

    #[test]
    fn test_parse_response_valid() {
        // nosemgrep: aws-access-token, generic-api-key
        let body = r#"{
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                "credentials": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "sessionToken": "FwoGZXIvYXdzEBYaD",
                    "expiration": "2026-03-12T13:00:00Z"
                }
            }]
        }"#;

        let creds = parse_response(body, "arn:aws:iam::123456789012:role/TestRole").unwrap();
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE"); // nosemgrep
        assert_eq!(creds.secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); // nosemgrep
        assert_eq!(creds.session_token, "FwoGZXIvYXdzEBYaD");
    }

    #[test]
    fn test_parse_response_rejects_mismatched_role() {
        let body = r#"{
            "credentialSet": [{
                "roleArn": "arn:aws:iam::123456789012:role/OtherRole",
                "credentials": {
                    "accessKeyId": "synthetic-access",
                    "secretAccessKey": "synthetic-secret",
                    "sessionToken": "synthetic-token",
                    "expiration": "2030-03-12T13:00:00Z"
                }
            }]
        }"#;

        let err = parse_response(
            body,
            "arn:aws:iam::123456789012:role/TestRole",
        )
        .unwrap_err();
        match err {
            YubiraError::Api(msg) => assert_eq!(
                msg,
                "Returned role does not match requested role"
            ),
            _ => panic!("Expected Api error"),
        }
    }

    #[test]
    fn test_parse_response_empty_credential_set() {
        let body = r#"{"credentialSet": []}"#;
        let err = parse_response(body, "arn:aws:iam::123456789012:role/TestRole").unwrap_err();
        match err {
            YubiraError::Api(msg) => assert!(msg.contains("No credentials")),
            _ => panic!("Expected Api error"),
        }
    }

    #[test]
    fn test_parse_response_invalid_json() {
        let err = parse_response(
            "not json",
            "arn:aws:iam::123456789012:role/TestRole",
        )
        .unwrap_err();
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
                "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                "credentials": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "sessionToken": "token",
                    "expiration": "not-a-date"
                }
            }]
        }"#;
        let err = parse_response(body, "arn:aws:iam::123456789012:role/TestRole").unwrap_err();
        match err {
            YubiraError::Api(msg) => assert!(msg.contains("expiration")),
            _ => panic!("Expected Api error"),
        }
    }

    #[test]
    fn test_credentials_debug_is_redacted() {
        let credentials = AWSCredentials {
            access_key_id: "synthetic-access-key".into(),
            secret_access_key: "synthetic-secret-key".into(),
            session_token: "synthetic-session-token".into(),
            expiration: Utc::now(),
        };

        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains("synthetic-access-key"));
        assert!(!rendered.contains("synthetic-secret-key"));
        assert!(!rendered.contains("synthetic-session-token"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn test_credentials_can_be_zeroized() {
        let mut credentials = AWSCredentials {
            access_key_id: "synthetic-access-key".into(),
            secret_access_key: "synthetic-secret-key".into(),
            session_token: "synthetic-session-token".into(),
            expiration: Utc::now(),
        };

        credentials.zeroize();
        assert!(credentials.access_key_id.is_empty());
        assert!(credentials.secret_access_key.is_empty());
        assert!(credentials.session_token.is_empty());
    }

    #[test]
    fn test_debug_request_omits_replayable_material() {
        let mut headers = BTreeMap::new();
        headers.insert("host".into(), "rolesanywhere.us-east-1.amazonaws.com".into());
        headers.insert("content-type".into(), "application/json".into());
        headers.insert("x-amz-x509".into(), "synthetic-certificate".into());
        headers.insert(
            "x-amz-x509-chain".into(),
            "synthetic-intermediate-chain".into(),
        );
        let rendered = format_debug_request(
            "https://rolesanywhere.us-east-1.amazonaws.com/sessions?roleArn=secret-role",
            &headers,
            b"{\"durationSeconds\":3600}",
            "canonical:synthetic-certificate:secret-key",
            "string-to-sign:synthetic-session-token",
            &Utc::now(),
        );

        for secret in [
            "roleArn=secret-role",
            "synthetic-certificate",
            "synthetic-intermediate-chain",
            "secret-key",
            "synthetic-session-token",
            "canonical:",
            "string-to-sign:",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.contains("?<redacted>"));
        assert!(rendered.contains("x-amz-x509: <redacted>"));
        assert!(rendered.contains("x-amz-x509-chain: <redacted>"));
        assert!(rendered.contains("Canonical request SHA-256:"));
        assert!(rendered.contains("String-to-sign SHA-256:"));
    }

    #[test]
    fn test_debug_response_omits_body() {
        let rendered = format_debug_response(201);
        assert!(rendered.contains("Status: 201"));
        assert!(rendered.contains("Body: <redacted>"));
    }
}
