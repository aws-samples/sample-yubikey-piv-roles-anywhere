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

use crate::error::YubiraError;

const ENV_VAR: &str = "YUBIKEY_PIV_PIN";

/// Get PIN automatically: prefer environment variable, fall back to interactive prompt.
pub fn get_pin_auto() -> Result<String, YubiraError> {
    if let Ok(pin) = env::var(ENV_VAR) {
        return Ok(pin);
    }

    rpassword::prompt_password("Enter YubiKey PIV PIN: ")
        .map_err(|e| YubiraError::PinError(format!("Failed to read PIN: {e}")))
}

/// Verify PIN with the YubiKey.
pub fn verify_pin(yubikey: &mut YubiKey, pin: &str) -> Result<(), YubiraError> {
    let pin_bytes = pin.as_bytes();
    yubikey.verify_pin(pin_bytes).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("blocked") {
            YubiraError::PinError("PIN is blocked. Use PUK to unblock.".to_string())
        } else {
            YubiraError::PinError(format!("Incorrect PIN: {msg}"))
        }
    })
}
