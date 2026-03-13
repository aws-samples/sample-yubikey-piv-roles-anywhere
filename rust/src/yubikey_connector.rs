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

//! YubiKey device detection and connection management.

use yubikey::YubiKey;

use crate::error::YubiraError;

/// Connect to a YubiKey, optionally filtering by serial number.
pub fn connect(serial: Option<u32>) -> Result<YubiKey, YubiraError> {
    match serial {
        Some(serial_num) => {
            let serial = yubikey::Serial::from(serial_num);
            YubiKey::open_by_serial(serial).map_err(|e| {
                if e.to_string().contains("not found") {
                    YubiraError::NoDevice(format!(
                        "YubiKey with serial {serial_num} not found."
                    ))
                } else {
                    YubiraError::ConnectionFailed(e.to_string())
                }
            })
        }
        None => YubiKey::open().map_err(|e| {
            if e.to_string().contains("not found") {
                YubiraError::NoDevice(
                    "No YubiKey detected. Please insert a YubiKey.".to_string(),
                )
            } else {
                YubiraError::ConnectionFailed(e.to_string())
            }
        }),
    }
}

/// List serial numbers of all connected YubiKeys.
#[allow(dead_code)]
pub fn list_serials() -> Result<Vec<u32>, YubiraError> {
    let mut readers = yubikey::reader::Context::open()
        .map_err(|e| YubiraError::ConnectionFailed(e.to_string()))?;

    let mut serials = Vec::new();
    for reader in readers
        .iter()
        .map_err(|e| YubiraError::ConnectionFailed(e.to_string()))?
    {
        if let Ok(yk) = reader.open() {
            serials.push(u32::from(yk.serial()));
        }
    }
    Ok(serials)
}
