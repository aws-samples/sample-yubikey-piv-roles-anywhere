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

//! YubiKey IAM Roles Anywhere credential process.

mod certificate_reader;
mod error;
mod pin_handler;
mod request_signer;
mod roles_anywhere_client;
mod yubikey_connector;

use clap::Parser;
use std::process;

use crate::error::YubiraError;

/// YubiKey IAM Roles Anywhere credential process.
///
/// Get AWS credentials using X.509 certificates stored on a YubiKey
/// via IAM Roles Anywhere.
#[derive(Parser, Debug)]
#[command(name = "yubira", version, about)]
struct Cli {
    /// ARN of the IAM Roles Anywhere trust anchor
    #[arg(long)]
    trust_anchor_arn: String,

    /// ARN of the IAM Roles Anywhere profile
    #[arg(long)]
    profile_arn: String,

    /// ARN of the IAM role to assume
    #[arg(long)]
    role_arn: String,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// PIV slot containing the certificate (9a, 9c, 9d, 9e)
    #[arg(long, default_value = "9a")]
    slot: String,

    /// YubiKey serial number (if multiple devices connected)
    #[arg(long)]
    serial: Option<u32>,

    /// Session duration in seconds
    #[arg(long, default_value_t = 3600)]
    session_duration: u32,

    /// Enable debug output (prints request details to stderr)
    #[arg(long)]
    debug: bool,
}

fn run(cli: &Cli) -> Result<(), YubiraError> {
    // Parse slot
    let slot = certificate_reader::parse_slot(&cli.slot)?;

    // Connect to YubiKey
    let mut yubikey = yubikey_connector::connect(cli.serial)?;

    // Read certificate from slot
    let cert_info = certificate_reader::read_certificate(&mut yubikey, slot)?;

    // Check expiration
    if cert_info.is_expired() {
        return Err(YubiraError::CertificateExpired(
            cert_info.not_after.format("%Y-%m-%d").to_string(),
        ));
    }

    // Handle PIN
    let pin = pin_handler::get_pin_auto()?;
    pin_handler::verify_pin(&mut yubikey, &pin)?;

    // Sign and call CreateSession
    let credentials = roles_anywhere_client::create_session(
        &mut yubikey,
        slot,
        &cert_info,
        &cli.trust_anchor_arn,
        &cli.profile_arn,
        &cli.role_arn,
        &cli.region,
        cli.session_duration,
        cli.debug,
    )?;

    // Output credentials as JSON to stdout
    let output = credentials.to_credential_process_output();
    println!("{}", serde_json::to_string(&output).map_err(|e| {
        YubiraError::Api(format!("Failed to serialize credentials: {e}"))
    })?);

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(&cli) {
        eprintln!("Error: {err}");
        process::exit(err.exit_code() as i32);
    }
}
