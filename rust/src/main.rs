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

mod certificate_chain;
mod certificate_reader;
mod error;
mod input_validation;
mod pin_handler;
mod request_signer;
mod roles_anywhere_client;
mod yubikey_connector;

use clap::Parser;
use std::io::{self, Write};
use std::path::PathBuf;
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

    /// Optional PEM bundle of up to five intermediates, leaf issuer first
    #[arg(long)]
    certificate_chain: Option<PathBuf>,

    /// Session duration in seconds
    #[arg(long, default_value_t = 3600)]
    session_duration: u32,

    /// Enable redacted diagnostics (never prints credentials or signed requests)
    #[arg(long)]
    debug: bool,
}

fn run(cli: &Cli) -> Result<(), YubiraError> {
    // Parse slot
    let slot = certificate_reader::parse_slot(&cli.slot)?;

    input_validation::validate_configuration(
        &cli.trust_anchor_arn,
        &cli.profile_arn,
        &cli.role_arn,
        &cli.region,
        cli.session_duration,
    )?;

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
    if cert_info.is_not_yet_valid() {
        return Err(YubiraError::CertificateNotYetValid(
            cert_info.not_before.format("%Y-%m-%d").to_string(),
        ));
    }

    let certificate_chain = cli
        .certificate_chain
        .as_deref()
        .map(|path| certificate_chain::load_certificate_chain(path, cert_info.to_der()))
        .transpose()?;

    // Acquire and verify the PIN in a short scope. Zeroizing<String> scrubs its
    // owned allocation before signing or credential acquisition begins.
    {
        let pin = pin_handler::get_pin_auto()?;
        pin_handler::verify_pin(&mut yubikey, pin.as_str())?;
    }

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
        certificate_chain.as_deref(),
        cli.debug,
    )?;

    // Serialize directly to locked stdout to avoid another aggregate secret copy.
    let output = credentials.to_credential_process_output();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &output)
        .map_err(|e| YubiraError::Api(format!("Failed to serialize credentials: {e}")))?;
    stdout
        .write_all(b"\n")
        .map_err(|e| YubiraError::Api(format!("Failed to write credentials: {e}")))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(&cli) {
        eprintln!("Error: {err}");
        process::exit(err.exit_code() as i32);
    }
}
