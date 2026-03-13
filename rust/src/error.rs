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

//! Error types and exit codes for yubira.

use std::fmt;

/// Exit codes matching the Python implementation.
#[repr(u8)]
pub enum ExitCode {
    NoDevice = 1,
    ConnectionFailed = 2,
    NoCertificate = 3,
    PinError = 4,
    CertificateExpired = 5,
    ApiError = 6,
    NetworkError = 7,
}

/// Unified error type for all yubira operations.
#[derive(Debug)]
pub enum YubiraError {
    /// No YubiKey detected or serial not found.
    NoDevice(String),
    /// Connection to YubiKey failed.
    ConnectionFailed(String),
    /// No certificate in specified slot.
    NoCertificate(String),
    /// PIN error (incorrect, blocked, or required).
    PinError(String),
    /// Certificate has expired.
    CertificateExpired(String),
    /// IAM Roles Anywhere API error.
    Api(String),
    /// Network error.
    Network(String),
    /// Signing error.
    Signing(String),
    /// Invalid slot.
    InvalidSlot(String),
}

impl YubiraError {
    /// Map error to its exit code.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::NoDevice(_) => ExitCode::NoDevice,
            Self::ConnectionFailed(_) => ExitCode::ConnectionFailed,
            Self::NoCertificate(_) | Self::InvalidSlot(_) => ExitCode::NoCertificate,
            Self::PinError(_) => ExitCode::PinError,
            Self::CertificateExpired(_) => ExitCode::CertificateExpired,
            Self::Api(_) | Self::Signing(_) => ExitCode::ApiError,
            Self::Network(_) => ExitCode::NetworkError,
        }
    }
}

impl fmt::Display for YubiraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice(msg) => write!(f, "{msg}"),
            Self::ConnectionFailed(msg) => write!(f, "Failed to connect to YubiKey: {msg}"),
            Self::NoCertificate(msg) => write!(f, "{msg}"),
            Self::PinError(msg) => write!(f, "{msg}"),
            Self::CertificateExpired(date) => write!(f, "Certificate expired on {date}."),
            Self::Api(msg) => write!(f, "CreateSession failed: {msg}"),
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::Signing(msg) => write!(f, "Signing failed: {msg}"),
            Self::InvalidSlot(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for YubiraError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_no_device() {
        let err = YubiraError::NoDevice("not found".into());
        assert_eq!(err.exit_code() as u8, 1);
    }

    #[test]
    fn test_exit_code_connection_failed() {
        let err = YubiraError::ConnectionFailed("timeout".into());
        assert_eq!(err.exit_code() as u8, 2);
    }

    #[test]
    fn test_exit_code_no_certificate() {
        let err = YubiraError::NoCertificate("empty slot".into());
        assert_eq!(err.exit_code() as u8, 3);
    }

    #[test]
    fn test_exit_code_invalid_slot() {
        let err = YubiraError::InvalidSlot("bad slot".into());
        assert_eq!(err.exit_code() as u8, 3);
    }

    #[test]
    fn test_exit_code_pin_error() {
        let err = YubiraError::PinError("wrong pin".into());
        assert_eq!(err.exit_code() as u8, 4);
    }

    #[test]
    fn test_exit_code_certificate_expired() {
        let err = YubiraError::CertificateExpired("2024-01-01".into());
        assert_eq!(err.exit_code() as u8, 5);
    }

    #[test]
    fn test_exit_code_api_error() {
        let err = YubiraError::Api("bad request".into());
        assert_eq!(err.exit_code() as u8, 6);
    }

    #[test]
    fn test_exit_code_signing_error() {
        let err = YubiraError::Signing("failed".into());
        assert_eq!(err.exit_code() as u8, 6);
    }

    #[test]
    fn test_exit_code_network_error() {
        let err = YubiraError::Network("dns failed".into());
        assert_eq!(err.exit_code() as u8, 7);
    }

    #[test]
    fn test_display_no_device() {
        let err = YubiraError::NoDevice("not found".into());
        assert_eq!(format!("{err}"), "not found");
    }

    #[test]
    fn test_display_connection_failed() {
        let err = YubiraError::ConnectionFailed("timeout".into());
        assert_eq!(format!("{err}"), "Failed to connect to YubiKey: timeout");
    }

    #[test]
    fn test_display_certificate_expired() {
        let err = YubiraError::CertificateExpired("2024-01-01".into());
        assert_eq!(format!("{err}"), "Certificate expired on 2024-01-01.");
    }

    #[test]
    fn test_display_api_error() {
        let err = YubiraError::Api("invalid signature".into());
        assert_eq!(format!("{err}"), "CreateSession failed: invalid signature");
    }

    #[test]
    fn test_display_network_error() {
        let err = YubiraError::Network("dns failed".into());
        assert_eq!(format!("{err}"), "Network error: dns failed");
    }

    #[test]
    fn test_display_signing_error() {
        let err = YubiraError::Signing("key error".into());
        assert_eq!(format!("{err}"), "Signing failed: key error");
    }

    #[test]
    fn test_display_invalid_slot() {
        let err = YubiraError::InvalidSlot("bad slot".into());
        assert_eq!(format!("{err}"), "bad slot");
    }

    #[test]
    fn test_display_pin_error() {
        let err = YubiraError::PinError("wrong".into());
        assert_eq!(format!("{err}"), "wrong");
    }

    #[test]
    fn test_display_no_certificate() {
        let err = YubiraError::NoCertificate("empty".into());
        assert_eq!(format!("{err}"), "empty");
    }

    #[test]
    fn test_error_is_std_error() {
        let err = YubiraError::Api("test".into());
        let _: &dyn std::error::Error = &err;
    }
}
