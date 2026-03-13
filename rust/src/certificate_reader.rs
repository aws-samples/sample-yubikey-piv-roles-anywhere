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

//! Certificate reader for X.509 certificates from YubiKey PIV slots.

use chrono::{DateTime, Utc};
use der::Encode;
use yubikey::certificate::Certificate;
use yubikey::piv::SlotId;
use yubikey::YubiKey;

use crate::error::YubiraError;

/// Key type detected from the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    EcP256,
    EcP384,
}

/// Information about a certificate stored in a YubiKey PIV slot.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CertificateInfo {
    /// DER-encoded certificate bytes.
    pub der_bytes: Vec<u8>,
    /// The PIV slot this certificate was read from.
    pub slot: SlotId,
    /// Subject common name.
    pub subject: String,
    /// Certificate serial number (decimal string).
    pub serial_number: String,
    /// Not valid before.
    pub not_before: DateTime<Utc>,
    /// Not valid after.
    pub not_after: DateTime<Utc>,
    /// Key type (RSA or EC).
    pub key_type: KeyType,
}

impl CertificateInfo {
    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Return the DER-encoded certificate bytes.
    pub fn to_der(&self) -> &[u8] {
        &self.der_bytes
    }
}

/// Parse a slot string (e.g., "9a") to a PIV SlotId.
pub fn parse_slot(slot_str: &str) -> Result<SlotId, YubiraError> {
    match slot_str.to_lowercase().as_str() {
        "9a" => Ok(SlotId::Authentication),
        "9c" => Ok(SlotId::Signature),
        "9d" => Ok(SlotId::KeyManagement),
        "9e" => Ok(SlotId::CardAuthentication),
        _ => Err(YubiraError::InvalidSlot(format!(
            "Invalid slot '{slot_str}'. Valid slots are: 9a, 9c, 9d, 9e"
        ))),
    }
}

/// Read a certificate from the specified PIV slot.
pub fn read_certificate(
    yubikey: &mut YubiKey,
    slot: SlotId,
) -> Result<CertificateInfo, YubiraError> {
    let yk_cert = Certificate::read(yubikey, slot).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("InvalidObject") || msg.contains("not found") || msg.contains("no data") {
            let slot_name = slot_display_name(slot);
            YubiraError::NoCertificate(format!("No certificate found in slot {slot_name}."))
        } else {
            YubiraError::NoCertificate(format!("Failed to read certificate from slot: {msg}"))
        }
    })?;

    // The yubikey crate's Certificate wraps x509_cert::Certificate
    let x509 = &yk_cert.cert;
    let tbs = &x509.tbs_certificate;

    // Get DER bytes from the inner certificate
    let der_bytes = x509.to_der().map_err(|e| {
        YubiraError::NoCertificate(format!("Failed to encode certificate as DER: {e}"))
    })?;

    // Extract serial number as decimal string
    let serial_bytes = tbs.serial_number.as_bytes();
    let serial_number = serial_bytes
        .iter()
        .fold(num_bigint_dig::BigUint::from(0u32), |acc, &b| {
            acc * 256u32 + u32::from(b)
        })
        .to_string();

    // Extract subject CN
    let subject = yk_cert.subject();

    // Extract validity dates
    let not_before = parse_x509_time(&tbs.validity.not_before)?;
    let not_after = parse_x509_time(&tbs.validity.not_after)?;

    // Determine key type
    let key_type = detect_key_type(&tbs.subject_public_key_info)?;

    Ok(CertificateInfo {
        der_bytes,
        slot,
        subject,
        serial_number,
        not_before,
        not_after,
        key_type,
    })
}

fn slot_display_name(slot: SlotId) -> &'static str {
    match slot {
        SlotId::Authentication => "9a (Authentication)",
        SlotId::Signature => "9c (Digital Signature)",
        SlotId::KeyManagement => "9d (Key Management)",
        SlotId::CardAuthentication => "9e (Card Authentication)",
        _ => "unknown",
    }
}

fn parse_x509_time(time: &x509_cert::time::Time) -> Result<DateTime<Utc>, YubiraError> {
    let dt: std::time::SystemTime = (*time).into();
    Ok(DateTime::<Utc>::from(dt))
}

fn detect_key_type(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<KeyType, YubiraError> {
    use der::oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_384_R_1};

    let alg_oid = &spki.algorithm.oid;

    if *alg_oid == RSA_ENCRYPTION {
        return Ok(KeyType::Rsa);
    }

    if *alg_oid == ID_EC_PUBLIC_KEY {
        if let Some(params) = &spki.algorithm.parameters {
            let curve_oid =
                params
                    .decode_as::<der::asn1::ObjectIdentifier>()
                    .map_err(|e| {
                        YubiraError::NoCertificate(format!("Failed to parse EC curve OID: {e}"))
                    })?;
            if curve_oid == SECP_384_R_1 {
                return Ok(KeyType::EcP384);
            }
            return Ok(KeyType::EcP256);
        }
        return Ok(KeyType::EcP256);
    }

    Err(YubiraError::NoCertificate(format!(
        "Unsupported key type OID: {alg_oid}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_slot_9a() {
        assert_eq!(parse_slot("9a").unwrap(), SlotId::Authentication);
    }

    #[test]
    fn test_parse_slot_9c() {
        assert_eq!(parse_slot("9c").unwrap(), SlotId::Signature);
    }

    #[test]
    fn test_parse_slot_9d() {
        assert_eq!(parse_slot("9d").unwrap(), SlotId::KeyManagement);
    }

    #[test]
    fn test_parse_slot_9e() {
        assert_eq!(parse_slot("9e").unwrap(), SlotId::CardAuthentication);
    }

    #[test]
    fn test_parse_slot_uppercase() {
        assert_eq!(parse_slot("9A").unwrap(), SlotId::Authentication);
        assert_eq!(parse_slot("9C").unwrap(), SlotId::Signature);
    }

    #[test]
    fn test_parse_slot_invalid() {
        let err = parse_slot("9b").unwrap_err();
        match err {
            YubiraError::InvalidSlot(msg) => {
                assert!(msg.contains("9b"));
                assert!(msg.contains("Valid slots"));
            }
            _ => panic!("Expected InvalidSlot error"),
        }
    }

    #[test]
    fn test_parse_slot_empty() {
        assert!(parse_slot("").is_err());
    }

    #[test]
    fn test_parse_slot_garbage() {
        assert!(parse_slot("xx").is_err());
        assert!(parse_slot("123").is_err());
    }

    #[test]
    fn test_slot_display_name() {
        assert_eq!(slot_display_name(SlotId::Authentication), "9a (Authentication)");
        assert_eq!(slot_display_name(SlotId::Signature), "9c (Digital Signature)");
        assert_eq!(slot_display_name(SlotId::KeyManagement), "9d (Key Management)");
        assert_eq!(slot_display_name(SlotId::CardAuthentication), "9e (Card Authentication)");
    }

    #[test]
    fn test_certificate_info_is_expired() {
        let expired = CertificateInfo {
            der_bytes: vec![],
            slot: SlotId::Authentication,
            subject: "CN=test".into(),
            serial_number: "12345".into(),
            not_before: Utc::now() - chrono::Duration::days(365),
            not_after: Utc::now() - chrono::Duration::days(1),
            key_type: KeyType::Rsa,
        };
        assert!(expired.is_expired());
    }

    #[test]
    fn test_certificate_info_not_expired() {
        let valid = CertificateInfo {
            der_bytes: vec![1, 2, 3],
            slot: SlotId::Authentication,
            subject: "CN=test".into(),
            serial_number: "12345".into(),
            not_before: Utc::now() - chrono::Duration::days(30),
            not_after: Utc::now() + chrono::Duration::days(335),
            key_type: KeyType::EcP256,
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_certificate_info_to_der() {
        let info = CertificateInfo {
            der_bytes: vec![0x30, 0x82, 0x01],
            slot: SlotId::Authentication,
            subject: "CN=test".into(),
            serial_number: "1".into(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            key_type: KeyType::Rsa,
        };
        assert_eq!(info.to_der(), &[0x30, 0x82, 0x01]);
    }

    #[test]
    fn test_key_type_equality() {
        assert_eq!(KeyType::Rsa, KeyType::Rsa);
        assert_eq!(KeyType::EcP256, KeyType::EcP256);
        assert_eq!(KeyType::EcP384, KeyType::EcP384);
        assert_ne!(KeyType::Rsa, KeyType::EcP256);
    }
}
