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

//! Optional intermediate-certificate chain loading and validation.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::error::YubiraError;

pub const MAX_CHAIN_CERTIFICATES: usize = 5;
const MAX_CHAIN_FILE_BYTES: u64 = 64 * 1024;

fn chain_error(message: impl Into<String>) -> YubiraError {
    YubiraError::InvalidConfiguration(message.into())
}

fn ordered_from_leaf(leaf_issuer: &Name, links: &[(Name, Name)]) -> bool {
    let mut expected_issuer = leaf_issuer;
    for (subject, issuer) in links {
        if subject != expected_issuer {
            return false;
        }
        expected_issuer = issuer;
    }
    true
}

pub fn validate_certificate_chain(
    leaf_der: &[u8],
    chain_der: &[Vec<u8>],
) -> Result<(), YubiraError> {
    if chain_der.is_empty() {
        return Err(chain_error("certificate chain is empty"));
    }
    if chain_der.len() > MAX_CHAIN_CERTIFICATES {
        return Err(chain_error("certificate chain exceeds five certificates"));
    }

    let leaf = Certificate::from_der(leaf_der)
        .map_err(|_| chain_error("leaf certificate contains invalid DER"))?;
    let chain: Vec<_> = chain_der
        .iter()
        .map(|item| {
            Certificate::from_der(item)
                .map_err(|_| chain_error("certificate chain contains invalid DER"))
        })
        .collect::<Result<_, _>>()?;

    let mut fingerprints = HashSet::new();
    fingerprints.insert(leaf_der.to_vec());
    for encoded in chain_der {
        if !fingerprints.insert(encoded.clone()) {
            return Err(chain_error(
                "certificate chain contains a duplicate certificate",
            ));
        }
    }

    let links: Vec<_> = chain
        .iter()
        .map(|cert| {
            (
                cert.tbs_certificate.subject.clone(),
                cert.tbs_certificate.issuer.clone(),
            )
        })
        .collect();
    if !ordered_from_leaf(&leaf.tbs_certificate.issuer, &links) {
        return Err(chain_error(
            "certificate chain is not ordered from the leaf issuer",
        ));
    }
    Ok(())
}

pub fn load_certificate_chain(path: &Path, leaf_der: &[u8]) -> Result<Vec<Vec<u8>>, YubiraError> {
    let metadata =
        fs::metadata(path).map_err(|_| chain_error("certificate chain file cannot be read"))?;
    if metadata.len() > MAX_CHAIN_FILE_BYTES {
        return Err(chain_error("certificate chain file exceeds 65536 bytes"));
    }
    let pem_data =
        fs::read(path).map_err(|_| chain_error("certificate chain file cannot be read"))?;
    if pem_data.len() as u64 > MAX_CHAIN_FILE_BYTES {
        return Err(chain_error("certificate chain file exceeds 65536 bytes"));
    }
    if pem_data.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(chain_error("certificate chain is empty"));
    }
    let certificates = Certificate::load_pem_chain(&pem_data)
        .map_err(|_| chain_error("certificate chain file is not valid PEM"))?;
    let chain_der = certificates
        .iter()
        .map(|cert| {
            cert.to_der()
                .map_err(|_| chain_error("certificate chain contains invalid DER"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_certificate_chain(leaf_der, &chain_der)?;
    Ok(chain_der)
}

pub fn encode_certificate_chain(chain_der: &[Vec<u8>]) -> String {
    use base64::Engine;

    chain_der
        .iter()
        .map(|item| base64::engine::general_purpose::STANDARD.encode(item))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encodes_comma_delimited_base64_der() {
        assert_eq!(
            encode_certificate_chain(&[b"one".to_vec(), b"two".to_vec()]),
            "b25l,dHdv"
        );
    }

    #[test]
    fn accepts_leaf_issuer_first_name_order() {
        let intermediate = Name::from_str("CN=intermediate").unwrap();
        let root = Name::from_str("CN=root").unwrap();
        let links = vec![(intermediate.clone(), root.clone()), (root.clone(), root)];
        assert!(ordered_from_leaf(&intermediate, &links));
    }

    #[test]
    fn rejects_wrong_name_order() {
        let intermediate = Name::from_str("CN=intermediate").unwrap();
        let other = Name::from_str("CN=other").unwrap();
        let root = Name::from_str("CN=root").unwrap();
        assert!(!ordered_from_leaf(&intermediate, &[(other, root)],));
    }

    #[test]
    fn rejects_empty_and_excessive_chains_before_der_parsing() {
        assert!(validate_certificate_chain(&[], &[]).is_err());
        assert!(validate_certificate_chain(&[], &vec![vec![]; 6]).is_err());
    }

    #[test]
    fn rejects_malformed_pem_file() {
        let path = std::env::temp_dir().join(format!(
            "yubira-chain-test-{}-{}.pem",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        fs::write(&path, b"not a certificate").unwrap();
        let result = load_certificate_chain(&path, &[]);
        fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
