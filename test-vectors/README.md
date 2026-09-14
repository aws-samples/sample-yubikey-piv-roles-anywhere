# IAM Roles Anywhere Signing Vectors

`roles-anywhere-signing.json` is the language-neutral conformance source for Python and Rust canonical-request and string-to-sign tests.

## Authority

Expected values follow the AWS documentation:

- [IAM Roles Anywhere authentication signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html)
- [IAM Roles Anywhere authentication process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication.html)
- [IAM Roles Anywhere CreateSession API](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html)

The expected strings were calculated independently of either project implementation. Do not regenerate expected values by calling Yubira’s Python or Rust canonicalization functions; doing so would allow the implementations and vectors to share the same defect.

## Coverage

The vectors cover:

1. The fixed `/sessions` RSA request with encoded profile, role, and trust-anchor ARNs.
2. Required double encoding of spaces, literal percent escapes, and UTF-8 path data.
3. Duplicate query names, empty values, sorting, and double encoding of equals signs in values.
4. Canonical header ordering and whitespace normalization.
5. Payload hashes, signed-header lists, credential scopes, and complete strings-to-sign.
6. RSA, P-256, and P-384 Roles Anywhere algorithm identifiers.

They intentionally stop before hardware signature generation. Real RSA/ECDSA PIV operations require controlled YubiKey integration tests.

## Consumers

- Python: `python/tests/test_signing_vectors.py`
- Rust: inline tests in `rust/src/request_signer.rs`

Both consumers must pass for any vector change.

## Review requirements

Changes to a vector require:

1. A citation to the applicable AWS rule.
2. Independent calculation or an AWS-published expected value.
3. Review of every changed byte in `canonical_request` and `string_to_sign`.
4. Green Python and Rust suites.
