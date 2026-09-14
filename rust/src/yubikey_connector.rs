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

fn open_by_serial(serial_num: u32) -> Result<YubiKey, YubiraError> {
    let serial = yubikey::Serial::from(serial_num);
    YubiKey::open_by_serial(serial).map_err(|e| {
        if e.to_string().contains("not found") {
            YubiraError::NoDevice(format!("YubiKey with serial {serial_num} not found."))
        } else {
            YubiraError::ConnectionFailed(e.to_string())
        }
    })
}

fn select_only_serial(serials: &[u32]) -> Result<u32, YubiraError> {
    match serials {
        [] => Err(YubiraError::NoDevice(
            "No YubiKey detected. Please insert a YubiKey.".to_string(),
        )),
        [serial] => Ok(*serial),
        _ => Err(YubiraError::ConnectionFailed(
            "Multiple YubiKeys detected. Specify --serial.".to_string(),
        )),
    }
}

/// Connect to a YubiKey. An explicit serial remains optional when exactly one
/// device is connected and is required only when auto-selection is ambiguous.
pub fn connect(serial: Option<u32>) -> Result<YubiKey, YubiraError> {
    match serial {
        Some(serial_num) => open_by_serial(serial_num),
        None => open_by_serial(select_only_serial(&list_serials()?)?),
    }
}

/// List serial numbers of all connected YubiKeys.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_device_is_rejected() {
        let err = select_only_serial(&[]).unwrap_err();
        assert!(matches!(err, YubiraError::NoDevice(_)));
    }

    #[test]
    fn one_device_is_selected_without_serial_parameter() {
        assert_eq!(select_only_serial(&[12_345_678]).unwrap(), 12_345_678);
    }

    #[test]
    fn multiple_devices_require_serial_parameter() {
        let err = select_only_serial(&[11_111_111, 22_222_222]).unwrap_err();
        match err {
            YubiraError::ConnectionFailed(msg) => {
                assert_eq!(msg, "Multiple YubiKeys detected. Specify --serial.");
            }
            _ => panic!("Expected ConnectionFailed error"),
        }
    }
}
