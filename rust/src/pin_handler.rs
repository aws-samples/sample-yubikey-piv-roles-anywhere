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

//! PIN handler for YubiKey PIV PIN management.

use std::env;

use yubikey::YubiKey;
use zeroize::Zeroizing;

use crate::error::YubiraError;

const ENV_VAR: &str = "YUBIKEY_PIV_PIN";

/// Get a PIN without giving up noninteractive environment-based operation.
///
/// An environment PIN is consumed exactly once and removed from this process
/// before verification, preventing later child processes from inheriting it.
/// The returned allocation is zeroized when dropped.
pub fn get_pin_auto() -> Result<Zeroizing<String>, YubiraError> {
    match env::var(ENV_VAR) {
        Ok(pin) => {
            env::remove_var(ENV_VAR);
            return Ok(Zeroizing::new(pin));
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            env::remove_var(ENV_VAR);
            return Err(YubiraError::PinError(format!(
                "{ENV_VAR} must contain valid UTF-8"
            )));
        }
    }

    rpassword::prompt_password("Enter YubiKey PIV PIN: ")
        .map(Zeroizing::new)
        .map_err(|e| YubiraError::PinError(format!("Failed to read PIN: {e}")))
}

fn pin_verification_error(message: &str) -> YubiraError {
    if message.to_ascii_lowercase().contains("blocked") {
        YubiraError::PinError("PIN is blocked. Use PUK to unblock.".to_string())
    } else {
        // Do not propagate backend text into logs in case it contains sensitive
        // context. The PIN itself is never included in this error.
        YubiraError::PinError("Incorrect PIN.".to_string())
    }
}

/// Verify PIN with the YubiKey.
pub fn verify_pin(yubikey: &mut YubiKey, pin: &str) -> Result<(), YubiraError> {
    yubikey
        .verify_pin(pin.as_bytes())
        .map_err(|e| pin_verification_error(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::{Zeroize, Zeroizing};

    use super::{get_pin_auto, pin_verification_error, ENV_VAR};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn environment_pin_is_consumed_into_zeroizing_storage() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "synthetic-pin-value");

        let mut pin: Zeroizing<String> = get_pin_auto().unwrap();

        assert_eq!(pin.as_str(), "synthetic-pin-value");
        assert!(std::env::var_os(ENV_VAR).is_none());
        pin.zeroize();
        assert!(pin.is_empty());
    }

    #[test]
    fn verification_errors_do_not_echo_sensitive_backend_text() {
        let secret = "synthetic-pin-value";
        let error = pin_verification_error(&format!("wrong PIN supplied: {secret}"));
        let rendered = error.to_string();

        assert_eq!(rendered, "Incorrect PIN.");
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn blocked_error_remains_actionable_without_backend_details() {
        let error = pin_verification_error("credential blocked; internal=private");
        let rendered = error.to_string();

        assert_eq!(rendered, "PIN is blocked. Use PUK to unblock.");
        assert!(!rendered.contains("internal"));
    }
}
