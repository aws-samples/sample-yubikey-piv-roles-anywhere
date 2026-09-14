# Yubira - YubiKey IAM Roles Anywhere Authentication

Yubira is a credential helper that enables AWS CLI/SDK authentication using X.509 certificates stored on a YubiKey hardware token. It leverages the YubiKey's PIV (Personal Identity Verification) functionality to perform cryptographic signing operations without exposing private keys.

Available in two implementations:
- **Python** (`python/`) — Portable, easy to install via pip
- **Rust** (`rust/`) — Single static binary, no runtime dependencies

## Features

- **Hardware-backed security**: Private keys never leave the YubiKey
- **AWS credential process integration**: Works seamlessly with AWS CLI and SDKs
- **Multiple YubiKey support**: Select specific device by serial number
- **Flexible slot selection**: Use any PIV slot (9a, 9c, 9d, 9e)
- **RSA-2048 and ECDSA support**: Supports RSA-2048, P-256, and P-384 consistently in both implementations; RSA-1024/3072/4096 are rejected until stable Rust driver support is available

## Prerequisites

### Common
- YubiKey with PIV capability (YubiKey 4, 5, or later)
- X.509 certificate loaded in a PIV slot
- AWS IAM Roles Anywhere configured with:
  - Trust Anchor (CA that issued your certificate)
  - Profile (defines the IAM role and policies)
  - IAM Role (the role to assume)

> Before using Yubira for production or emergency access, complete the [Security Deployment Guide](docs/security-deployment.md). Hardware-backed keys do not replace least-privilege IAM trust, certificate lifecycle/revocation, monitoring, and a tested break-glass procedure.

### Python
- Python 3.13+

### Rust
- Rust 1.70+ (install via [rustup](https://rustup.rs))
- Platform-specific PC/SC dependencies:
  - **Linux**: `pkg-config` and `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora/RHEL)
  - **macOS**: PC/SC framework is included with the OS, no extra packages needed
  - **Windows**: WinSCard is included with Windows, no extra packages needed

## Installation

### Python

```bash
cd python

# Install from source
pip install .

# Or install in development mode
pip install -e .
```

### Rust

```bash
cd rust

# Build release binary
cargo build --release --locked

# The binary will be at rust/target/release/yubira (or yubira.exe on Windows)
```

Optionally install it system-wide:

```bash
cd rust

cargo install --path . --locked
```

After installation, the `yubira` command will be available in your PATH.

## Usage

### Command Line

```bash
yubira \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 \
  --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --region us-east-1
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--trust-anchor-arn` | ARN of the IAM Roles Anywhere trust anchor | Required |
| `--profile-arn` | ARN of the IAM Roles Anywhere profile | Required |
| `--role-arn` | ARN of the IAM role to assume | Required |
| `--region` | Commercial AWS or GovCloud region matching the Roles Anywhere ARNs | us-east-1 |
| `--slot` | PIV slot containing the certificate | 9a |
| `--serial` | YubiKey serial number; optional with one device, required when multiple are connected | Auto-select one device |
| `--certificate-chain` | Optional PEM bundle of up to five certificates, ordered from the leaf issuer toward the trust anchor | None |
| `--session-duration` | Session duration in seconds (900–43200) | 3600 |
| `--debug` | Print redacted diagnostic metadata and non-replayable hashes to stderr | Off |

### AWS CLI Integration

Before accessing the YubiKey, both implementations validate region syntax, the 900–43200 second duration, ARN services/resources/accounts/partitions, trust-anchor/profile coherence, and supported commercial AWS or GovCloud partition mapping. Cross-account target roles remain supported when partitions match. Unsupported partitions fail closed. Successful credentials are accepted only when the returned `roleArn` exactly matches the requested role.

Configure your AWS credentials file to use Yubira as a credential process.

The credentials file location:
- **Linux/macOS**: `~/.aws/credentials`
- **Windows**: `%USERPROFILE%\.aws\credentials`

#### Python

```ini
[yubikey]
credential_process = python -m yubira.cli --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 --role-arn arn:aws:iam::123456789012:role/MyRole --region us-east-1
```

This works on all platforms as long as the `yubira` package is installed in the Python environment that `python` resolves to.

#### Rust

On Windows:
```ini
[yubikey]
credential_process = yubira.exe --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 --role-arn arn:aws:iam::123456789012:role/MyRole --region us-east-1
```

On Linux/macOS:
```ini
[yubikey]
credential_process = yubira --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 --role-arn arn:aws:iam::123456789012:role/MyRole --region us-east-1
```

Then use the profile with any AWS CLI command:

```bash
aws s3 ls --profile yubikey
aws sts get-caller-identity --profile yubikey
```

### Using with Specific YubiKey

If you have multiple YubiKeys, specify the serial number:

```ini
[yubikey-work]
credential_process = yubira.exe --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 --role-arn arn:aws:iam::123456789012:role/MyRole --serial 12345678
```

### Using an Intermediate Certificate Chain

For a leaf certificate issued through intermediates, provide a PEM bundle ordered from the leaf issuer toward the configured trust anchor:

```ini
credential_process = yubira --trust-anchor-arn <TRUST_ANCHOR_ARN> --profile-arn <PROFILE_ARN> --role-arn <ROLE_ARN> --certificate-chain /path/to/intermediates.pem
```

The option accepts at most five certificates and a 64 KiB file. Yubira rejects malformed, duplicate, or incorrectly ordered chains. It sends the bundle as signed, comma-delimited base64 DER in `X-Amz-X509-Chain`; omit the option when the leaf chains directly to the trust anchor.

### Using Different PIV Slots

```ini
[yubikey-signing]
credential_process = yubira.exe --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc123 --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def456 --role-arn arn:aws:iam::123456789012:role/MyRole --slot 9c
```

### PIV Slot Reference

| Slot | Name | Typical Use |
|------|------|-------------|
| 9a | Authentication | General authentication (default) |
| 9c | Digital Signature | Document signing |
| 9d | Key Management | Encryption/decryption |
| 9e | Card Authentication | Physical access |

## PIN Handling

Yubira supports two methods for PIN entry:

1. **Environment variable**: Set `YUBIKEY_PIV_PIN` before running
   ```bash
   export YUBIKEY_PIV_PIN=123456
   aws s3 ls --profile yubikey
   ```

The child Yubira process consumes and removes its own `YUBIKEY_PIV_PIN` environment entry before verification so later child processes cannot inherit it. This does not remove the value from the invoking shell or AWS process, or erase environment snapshots captured before removal. Unset the variable in the caller as soon as the noninteractive operation finishes, and do not use a long-lived globally exported PIN.

2. **Interactive prompt**: If no environment variable is set, you'll be prompted

## Error Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | No YubiKey detected or serial not found |
| 2 | Connection to YubiKey failed |
| 3 | No certificate in specified slot |
| 4 | PIN error (incorrect or blocked) |
| 5 | Certificate validation error |
| 6 | IAM Roles Anywhere API error |
| 7 | Network error |

## Comparison with Other AWS MFA Methods

Yubira uses YubiKey hardware tokens with X.509 certificates via IAM Roles Anywhere. Here's how it compares to other authentication methods available in AWS IAM and AWS IAM Identity Center.

### Pros

- **Replaces static IAM users for emergency access** — No need to create long-lived IAM user credentials. The YubiKey certificate provides a hardware-bound identity that can be used for break-glass scenarios without maintaining static access keys.
- **Immune to password reset phishing** — PIN and fingerprint verification happen onboard the YubiKey itself, depending on device capabilities. There is no password to set in AWS IAM or AWS IAM Identity Center, so there is nothing for an attacker to reset or intercept through phishing.
- **Fully integrated in CLI** — Ships as a standard AWS credential helper, plugging directly into `~/.aws/credentials` with `credential_process`. No browser, no SSO portal, no manual token copy-paste.
- **Flexible temporary-credential issuance** — IAM role trust policies and IAM Roles Anywhere profiles can authorize multiple approved paths for issuing temporary AWS credentials without creating long-lived IAM user keys.
- **Certificate-derived audit identity** — IAM Roles Anywhere can preserve the original X.509 identity as the STS source identity through `sts:SetSourceIdentity`, improving attribution in CloudTrail.

### Cons

- **Certificate management overhead** — Managing X.509 certificates (issuance, renewal, revocation via a CA) may be perceived as more complex than managing passwords or TOTP tokens.
- **Multi-account scaling** — Using Yubira across multiple AWS accounts requires either configuring multiple CLI profiles (one per account) or setting up cross-account role assumption from the initial account.

## Development

### Python

#### Running Tests

```bash
cd python
pip install -e ".[dev]"
python -m pytest tests/ -v
```

#### Running Property-Based Tests

```bash
cd python
python -m pytest tests/properties/ -v
```

### Rust

#### Running Tests

```bash
cd rust
cargo test --locked
```

112 tests cover error handling, optional bounded certificate chains, input validation, unambiguous token selection, certificate validity and exact EC curve allowlisting, PIN environment consumption/zeroization and structured retry state, slot parsing, SigV4 request signing, canonical request construction, credential output formatting, and API response parsing. Hardware-dependent code (YubiKey operations) requires a physical device and is not covered by unit tests.

#### Building

```bash
cd rust

# Debug build
cargo build --locked

# Release build (optimized)
cargo build --release --locked
```

All normal Rust build, test, and installation commands use `--locked` so a stale `Cargo.lock` fails instead of being updated implicitly. For a network-isolated release after dependencies have been fetched:

```bash
cd rust
cargo fetch --locked
cargo build --release --frozen
```

#### Project Structure

```
rust/src/
├── main.rs                  # CLI entry point (clap)
├── error.rs                 # Error types and exit codes
├── input_validation.rs      # Region, ARN, partition, and duration validation
├── certificate_chain.rs     # Optional bounded intermediate-chain handling
├── certificate_reader.rs    # X.509 certificate reading from PIV slots
├── pin_handler.rs           # PIN entry (env var or interactive prompt)
├── request_signer.rs        # AWS SigV4-X509 request signing
├── roles_anywhere_client.rs # CreateSession API client
└── yubikey_connector.rs     # YubiKey device detection and connection
```

#### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `yubikey` | PIV operations (certificate read, PIN verify, signing) |
| `x509-cert`, `der` | X.509 certificate parsing |
| `sha2`, `pkcs1` | Request hashing and public RSA modulus inspection |
| `p256`, `p384`, `rsa` | Transitive cryptography used by stable `yubikey 0.8.0` |
| `ureq` | Blocking HTTP client |
| `clap` | CLI argument parsing |
| `chrono` | Timestamp handling |
| `proptest` | Property-based testing (dev) |

## License

This project is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file for details.
