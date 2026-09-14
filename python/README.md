# Yubira Python Credential Helper

Python implementation of Yubira, a credential helper that uses an X.509 certificate and private key stored in a YubiKey PIV slot to request temporary AWS credentials from IAM Roles Anywhere. The private key remains on the YubiKey.

For the complete project overview, IAM Roles Anywhere prerequisites, PIV slot guidance, comparison with the Rust implementation, and security considerations, see the [repository README](../README.md).

## Requirements

- Python 3.13 or later
- A YubiKey with PIV support
- An X.509 certificate and matching private key provisioned in a supported PIV slot
- IAM Roles Anywhere trust anchor, profile, and IAM role
- Platform PC/SC support:
  - Linux: `pkg-config` and `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora/RHEL)
  - macOS: built-in PC/SC framework
  - Windows: built-in WinSCard support

## Reproducible installation

Install the reviewed runtime dependency graph and then install Yubira without re-resolving dependencies:

```bash
cd python
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps .
```

For development and tests:

```bash
cd python
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps -e .
python -m pytest tests/ -v
```

`requirements.lock` and `requirements-dev.lock` are generated artifacts. Do not edit package versions or hashes manually. Regenerate them from `pyproject.toml` with the commands embedded in each file header:

```bash
uv pip compile pyproject.toml \
  --python-version 3.13 \
  --universal \
  --resolution highest \
  --generate-hashes \
  --output-file requirements.lock

uv pip compile pyproject.toml \
  --extra dev \
  --python-version 3.13 \
  --universal \
  --resolution highest \
  --generate-hashes \
  --output-file requirements-dev.lock
```

Commit changes to `pyproject.toml` and both lockfiles together.

## Usage

```bash
yubira \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/EXAMPLE \
  --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/EXAMPLE \
  --role-arn arn:aws:iam::123456789012:role/ExampleRole \
  --region us-east-1
```

Configure it as an AWS shared-config credential process:

```ini
[profile yubikey]
credential_process = yubira --trust-anchor-arn <TRUST_ANCHOR_ARN> --profile-arn <PROFILE_ARN> --role-arn <ROLE_ARN> --region <REGION>
```


Yubira validates region syntax, session duration, ARN structure/service/resource/account/partition relationships, and supported commercial AWS/GovCloud mapping before token access. Cross-account target roles are allowed when partitions match. The returned `roleArn` must exactly match the requested role before credentials are emitted.

For an intermediate-CA topology, add `--certificate-chain /path/to/intermediates.pem` to the credential-process command. The PEM bundle must be ordered from the leaf issuer toward the trust anchor, contain at most five certificates, and be no larger than 64 KiB. Omit it for a leaf issued directly by the trust anchor. The resulting `X-Amz-X509-Chain` header is signed and redacted from diagnostics.
Then use the profile normally:

```bash
aws sts get-caller-identity --profile yubikey
```

## PIN handling

Yubira retains noninteractive operation through `YUBIKEY_PIV_PIN`. When present, the Python process consumes and removes its own environment entry before verification and deletes its local PIN reference immediately afterward. This prevents later child processes from inheriting the entry but cannot erase the parent shell/AWS process value, snapshots captured before removal, or the immutable Python string and runtime copies. Unset the caller's variable promptly after the operation and avoid long-lived global exports.

If no environment PIN is configured, Yubira prompts without terminal echo. Avoid placing PIV PINs in shell history, committed configuration, logs, or shared CI variables. Change factory PIV credentials before provisioning production or emergency-access keys, and configure an appropriate on-card touch policy.

## Security

Yubira emits temporary AWS credentials on stdout because that is required by the `credential_process` contract. Treat stdout, stderr, process memory, and troubleshooting artifacts as sensitive.

Python cannot reliably zero immutable strings or guarantee that interpreter, allocator, serializer, and operating-system buffers no longer contain a secret. The Python implementation minimizes exposure and redacts representations/debug output, but this remains a runtime limitation. Prefer the Rust implementation when explicit zeroization of in-process credential fields is part of the threat model; even Rust cannot erase copies already written to stdout, operating-system buffers, or the consuming AWS process.

Do not capture or share debug output from credential acquisition. Debug diagnostics redact credentials, certificate material, authorization data, ARN query values, canonical requests, strings-to-sign, and response bodies. Credential-process failures use fixed category-specific stderr messages rather than lower-level exception text; library callers may still inspect raised exception chains directly. Use least-privilege IAM role/profile policies, certificate attribute conditions, short sessions, certificate revocation procedures, and CloudTrail monitoring.

## Development

The test suite mocks hardware interactions; ordinary unit/property tests do not require a physical YubiKey. Live signing and IAM Roles Anywhere integration require separately controlled hardware and a non-production AWS environment.

```bash
python -m pytest tests/ -v
python -m pytest tests/properties/ -v
```

## License

This project is licensed under the MIT No Attribution (MIT-0) License. See the repository [LICENSE](../LICENSE).
