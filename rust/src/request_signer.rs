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

//! Request signer for IAM Roles Anywhere authentication (AWS SigV4 with X.509).

use chrono::{DateTime, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::YubiKey;

use crate::certificate_reader::KeyType;
use crate::error::YubiraError;

const SERVICE: &str = "rolesanywhere";
const ALGORITHM_PREFIX: &str = "AWS4-X509";

/// Characters that must NOT be percent-encoded in URI path segments.
/// Per RFC 3986: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
const URI_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Get the algorithm string for the Authorization header.
pub fn algorithm_string(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Rsa => "RSA-SHA256",
        KeyType::EcP256 => "ECDSA-SHA256",
        KeyType::EcP384 => "ECDSA-SHA384",
    }
}

/// Full algorithm identifier (e.g., "AWS4-X509-RSA-SHA256").
pub fn full_algorithm(key_type: KeyType) -> String {
    format!("{ALGORITHM_PREFIX}-{}", algorithm_string(key_type))
}

/// Compute SHA-256 hash of payload, returned as lowercase hex.
pub fn hash_payload(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// Create canonical request string per AWS SigV4 spec.
pub fn create_canonical_request(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &BTreeMap<String, String>,
    payload_hash: &str,
) -> String {
    let canonical_method = method.to_uppercase();
    let canonical_uri = uri_encode_path(uri);
    let canonical_query = create_canonical_query_string(query_string);
    let (canonical_headers, signed_headers) = create_canonical_headers(headers);

    format!(
        "{canonical_method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
}

/// Create string to sign per IAM Roles Anywhere spec.
pub fn create_string_to_sign(
    key_type: KeyType,
    timestamp: &DateTime<Utc>,
    region: &str,
    canonical_request: &str,
) -> String {
    let algorithm = full_algorithm(key_type);
    let request_datetime = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = timestamp.format("%Y%m%d").to_string();
    let credential_scope = format!("{date_stamp}/{region}/{SERVICE}/aws4_request");

    let mut hasher = Sha256::new();
    hasher.update(canonical_request.as_bytes());
    let hashed_canonical = hex::encode(hasher.finalize());

    format!("{algorithm}\n{request_datetime}\n{credential_scope}\n{hashed_canonical}")
}

/// Sign data using the YubiKey private key.
pub fn sign(
    yubikey: &mut YubiKey,
    slot: SlotId,
    key_type: KeyType,
    data: &[u8],
) -> Result<Vec<u8>, YubiraError> {
    let algorithm_id = match key_type {
        KeyType::Rsa => AlgorithmId::Rsa2048,
        KeyType::EcP256 => AlgorithmId::EccP256,
        KeyType::EcP384 => AlgorithmId::EccP384,
    };

    // Build the input for piv::sign_data.
    // For ECDSA: raw hash bytes.
    // For RSA: full PKCS#1 v1.5 padded block (key-size bytes).
    // The YubiKey performs raw RSA — we must provide the complete padded message.
    let sign_input: Vec<u8> = match key_type {
        KeyType::EcP384 => {
            use sha2::Sha384;
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        KeyType::EcP256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        KeyType::Rsa => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let hash = hasher.finalize();

            // Build DER-encoded DigestInfo for SHA-256 (RFC 3447 §9.2)
            let digest_info_prefix: &[u8] = &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                0x05, 0x00, 0x04, 0x20,
            ];

            // PKCS#1 v1.5 signature padding for RSA-2048 (256 bytes total):
            // 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || DigestInfo
            let key_len: usize = 256; // RSA-2048
            let t_len = digest_info_prefix.len() + hash.len(); // 19 + 32 = 51
            let ps_len = key_len - 3 - t_len; // 256 - 3 - 51 = 202

            let mut padded = Vec::with_capacity(key_len);
            padded.push(0x00);
            padded.push(0x01);
            padded.extend(std::iter::repeat(0xFF).take(ps_len));
            padded.push(0x00);
            padded.extend_from_slice(digest_info_prefix);
            padded.extend_from_slice(&hash);
            padded
        }
    };

    let signature = piv::sign_data(yubikey, &sign_input, algorithm_id, slot)
        .map_err(|e| YubiraError::Signing(e.to_string()))?;

    Ok(signature.to_vec())
}

/// Build the Authorization header value.
pub fn build_authorization_header(
    key_type: KeyType,
    cert_serial: &str,
    timestamp: &DateTime<Utc>,
    region: &str,
    signed_headers: &str,
    signature: &[u8],
) -> String {
    let algorithm = full_algorithm(key_type);
    let date_stamp = timestamp.format("%Y%m%d").to_string();
    let credential_scope = format!("{date_stamp}/{region}/{SERVICE}/aws4_request");

    format!(
        "{algorithm} Credential={cert_serial}/{credential_scope}, SignedHeaders={signed_headers}, Signature={}",
        hex::encode(signature)
    )
}

/// Get the signed headers string from a headers map.
pub fn get_signed_headers(headers: &BTreeMap<String, String>) -> String {
    headers.keys().cloned().collect::<Vec<_>>().join(";")
}

// --- Internal helpers ---

fn uri_encode_path(uri: &str) -> String {
    if uri.is_empty() {
        return "/".to_string();
    }

    let uri = if uri.starts_with('/') { uri.to_string() } else { format!("/{uri}") };

    uri.split('/')
        .map(|segment| {
            if segment.is_empty() {
                String::new()
            } else {
                utf8_percent_encode(segment, URI_ENCODE_SET).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn create_canonical_query_string(query_string: &str) -> String {
    if query_string.is_empty() {
        return String::new();
    }

    let mut params: Vec<(&str, &str)> = query_string
        .split('&')
        .map(|param| {
            if let Some((k, v)) = param.split_once('=') {
                (k, v)
            } else {
                (param, "")
            }
        })
        .collect();

    params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn create_canonical_headers(
    headers: &BTreeMap<String, String>,
) -> (String, String) {
    // BTreeMap is already sorted by key
    let canonical_lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            let trimmed = value.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("{name}:{trimmed}")
        })
        .collect();

    let canonical_headers = format!("{}\n", canonical_lines.join("\n"));
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");

    (canonical_headers, signed_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_payload_empty() {
        assert_eq!(
            hash_payload(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_uri_encode_path_empty() {
        assert_eq!(uri_encode_path(""), "/");
    }

    #[test]
    fn test_uri_encode_path_root() {
        assert_eq!(uri_encode_path("/"), "/");
    }

    #[test]
    fn test_uri_encode_path_sessions() {
        assert_eq!(uri_encode_path("/sessions"), "/sessions");
    }

    #[test]
    fn test_canonical_query_string_sorted() {
        assert_eq!(
            create_canonical_query_string("z=1&a=2&m=3"),
            "a=2&m=3&z=1"
        );
    }

    #[test]
    fn test_canonical_query_string_empty() {
        assert_eq!(create_canonical_query_string(""), "");
    }

    #[test]
    fn test_canonical_headers_sorted_lowercase() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.com".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let (canonical, signed) = create_canonical_headers(&headers);

        assert!(canonical.starts_with("content-type:application/json\n"));
        assert_eq!(signed, "content-type;host");
    }

    #[test]
    fn test_full_algorithm_rsa() {
        assert_eq!(full_algorithm(KeyType::Rsa), "AWS4-X509-RSA-SHA256");
    }

    #[test]
    fn test_full_algorithm_ec256() {
        assert_eq!(full_algorithm(KeyType::EcP256), "AWS4-X509-ECDSA-SHA256");
    }

    #[test]
    fn test_full_algorithm_ec384() {
        assert_eq!(full_algorithm(KeyType::EcP384), "AWS4-X509-ECDSA-SHA384");
    }

    #[test]
    fn test_algorithm_string_rsa() {
        assert_eq!(algorithm_string(KeyType::Rsa), "RSA-SHA256");
    }

    #[test]
    fn test_algorithm_string_ec256() {
        assert_eq!(algorithm_string(KeyType::EcP256), "ECDSA-SHA256");
    }

    #[test]
    fn test_algorithm_string_ec384() {
        assert_eq!(algorithm_string(KeyType::EcP384), "ECDSA-SHA384");
    }

    #[test]
    fn test_hash_payload_known_value() {
        // SHA-256 of "hello"
        assert_eq!(
            hash_payload(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_payload_json_body() {
        let body = b"{\"durationSeconds\":3600}";
        let hash = hash_payload(body);
        assert_eq!(hash.len(), 64); // SHA-256 hex is 64 chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_uri_encode_path_with_special_chars() {
        assert_eq!(uri_encode_path("/path with spaces"), "/path%20with%20spaces");
    }

    #[test]
    fn test_uri_encode_path_preserves_unreserved() {
        assert_eq!(uri_encode_path("/a-b_c.d~e"), "/a-b_c.d~e");
    }

    #[test]
    fn test_uri_encode_path_no_leading_slash() {
        assert_eq!(uri_encode_path("sessions"), "/sessions");
    }

    #[test]
    fn test_canonical_query_string_single_param() {
        assert_eq!(create_canonical_query_string("key=value"), "key=value");
    }

    #[test]
    fn test_canonical_query_string_no_value() {
        assert_eq!(create_canonical_query_string("key"), "key=");
    }

    #[test]
    fn test_canonical_headers_whitespace_trimming() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "  example.com  ".to_string());
        let (canonical, _) = create_canonical_headers(&headers);
        assert!(canonical.contains("host:example.com"));
    }

    #[test]
    fn test_canonical_headers_multi_space_collapse() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "a   b   c".to_string());
        let (canonical, _) = create_canonical_headers(&headers);
        assert!(canonical.contains("host:a b c"));
    }

    #[test]
    fn test_get_signed_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("host".to_string(), "example.com".to_string());
        headers.insert("x-amz-date".to_string(), "20260312T000000Z".to_string());
        assert_eq!(get_signed_headers(&headers), "content-type;host;x-amz-date");
    }

    #[test]
    fn test_create_canonical_request_structure() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "rolesanywhere.us-east-1.amazonaws.com".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let payload_hash = hash_payload(b"{}");
        let cr = create_canonical_request("POST", "/sessions", "", &headers, &payload_hash);

        let lines: Vec<&str> = cr.split('\n').collect();
        assert_eq!(lines[0], "POST");            // method
        assert_eq!(lines[1], "/sessions");        // URI
        assert_eq!(lines[2], "");                 // empty query string
        assert!(lines[3].starts_with("content-type:")); // first canonical header
        assert!(lines[4].starts_with("host:"));          // second canonical header
        // line 5 is empty (trailing newline from canonical headers block)
        assert_eq!(lines[6], "content-type;host");       // signed headers
        assert_eq!(lines[7], payload_hash);               // payload hash
    }

    #[test]
    fn test_create_string_to_sign_structure() {
        let ts = DateTime::parse_from_rfc3339("2026-03-12T10:30:00+00:00")
            .unwrap()
            .with_timezone(&Utc);

        let sts = create_string_to_sign(KeyType::Rsa, &ts, "us-east-1", "canonical-request");

        let lines: Vec<&str> = sts.split('\n').collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "AWS4-X509-RSA-SHA256");
        assert_eq!(lines[1], "20260312T103000Z");
        assert_eq!(lines[2], "20260312/us-east-1/rolesanywhere/aws4_request");
        // lines[3] is the SHA-256 of "canonical-request"
        assert_eq!(lines[3].len(), 64);
    }

    #[test]
    fn test_build_authorization_header_format() {
        let ts = DateTime::parse_from_rfc3339("2026-03-12T10:30:00+00:00")
            .unwrap()
            .with_timezone(&Utc);

        let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let auth = build_authorization_header(
            KeyType::Rsa,
            "123456789",
            &ts,
            "us-east-1",
            "content-type;host;x-amz-date;x-amz-x509",
            &sig,
        );

        assert!(auth.starts_with("AWS4-X509-RSA-SHA256 Credential=123456789/"));
        assert!(auth.contains("20260312/us-east-1/rolesanywhere/aws4_request"));
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-x509"));
        assert!(auth.contains("Signature=deadbeef"));
    }

    #[test]
    fn test_build_authorization_header_ec256() {
        let ts = Utc::now();
        let auth = build_authorization_header(
            KeyType::EcP256, "999", &ts, "eu-west-1", "host", &[0x01],
        );
        assert!(auth.starts_with("AWS4-X509-ECDSA-SHA256 "));
    }
}
