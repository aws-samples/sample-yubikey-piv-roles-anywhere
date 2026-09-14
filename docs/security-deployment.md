# Security Deployment Guide

This guide defines the external security controls required to deploy Yubira as an IAM Roles Anywhere credential helper, especially for emergency or break-glass access. Yubira signs a `CreateSession` request with a YubiKey-resident private key; it does not provision IAM, operate a certificate authority, configure the YubiKey, or enforce those systems’ policies.

## Security boundaries

Yubira is responsible for:

- selecting the configured YubiKey and PIV slot;
- reading the end-entity certificate;
- verifying the PIN in the Yubira execution path;
- constructing and signing the IAM Roles Anywhere request;
- validating TLS through the platform HTTP client;
- returning temporary credentials through the AWS `credential_process` contract.

External owners remain responsible for:

- YubiKey key generation/import and on-card PIN/touch policy;
- certificate issuance, inventory, renewal, and revocation;
- IAM Roles Anywhere trust anchors and profiles;
- IAM role trust and permission policies;
- CloudTrail retention, detections, and incident response;
- workstation, process, terminal, and credential-consumer security.

## Required IAM role trust

The target IAM role must trust the IAM Roles Anywhere service principal and permit the three STS actions used by the service:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "rolesanywhere.amazonaws.com"
      },
      "Action": [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity"
      ],
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:rolesanywhere:<REGION>:<ACCOUNT_ID>:trust-anchor/<TRUST_ANCHOR_ID>"
        },
        "StringEquals": {
          "aws:PrincipalTag/x509Subject/CN": "<EXPECTED_SUBJECT_CN>"
        }
      }
    }
  ]
}
```

Replace every placeholder and tailor certificate conditions to the issuing PKI. Do not deploy a service-principal-only trust statement without source and certificate-identity constraints.

IAM Roles Anywhere can expose certificate Subject, Issuer, and selected SAN fields as principal tags. Useful condition keys include:

- `aws:SourceArn` or `aws:SourceAccount` for the expected trust anchor/account;
- `aws:PrincipalTag/x509Subject/CN` and other Subject RDNs;
- `aws:PrincipalTag/x509Issuer/CN` and other Issuer RDNs;
- `aws:PrincipalTag/x509SAN/DNS`, `/URI`, or `/Name/...` where applicable;
- `sts:SourceIdentity` when its Roles Anywhere derivation rules fit the PKI identity model.

Review multi-valued RDN behavior: IAM Roles Anywhere joins repeated values with `/` in certificate order. Do not assume that an unvalidated display name is globally unique.

## Least-privilege role and profile

Use a dedicated role and profile for the exact emergency function:

1. Grant only required actions and resources.
2. Restrict the profile to approved role ARNs.
3. Use profile/session policies as additional restriction, not as a substitute for a minimal role.
4. Avoid general administrator access when task-specific recovery permissions suffice.
5. Keep production and non-production roles, profiles, and trust anchors separate.
6. Apply explicit cross-account trust conditions in every target account.
7. Review the effective intersection of role, profile, session, permission-boundary, SCP, and resource policies.

`CreateSession` supports 900–43200 seconds. The effective duration is also limited by the profile and target role. Use the shortest duration that supports the recovery procedure; Yubira defaults to 3600 seconds. Longer credentials increase exposure after stdout, process memory, or the consuming AWS client is compromised.

## Certificate requirements and lifecycle

IAM Roles Anywhere requires an end-entity X.509v3 certificate with:

- Basic Constraints absent or `CA: false`;
- Key Usage containing `Digital Signature`;
- a SHA-256-or-stronger certificate signature algorithm;
- a valid chain to the configured trust anchor.

Yubira’s stable cross-language implementation supports RSA-2048, ECDSA P-256, and ECDSA P-384. RSA continues to use the IAM Roles Anywhere-required `AWS4-X509-RSA-SHA256` identifier with SHA-256 and PKCS#1 v1.5. RSA-1024 is rejected as unsupported, and RSA-3072/4096 are rejected until the stable Rust YubiKey driver supports them; P-384 is the available higher-strength cross-language option.

Trust-anchor CA certificates require `CA: true`, `Certificate Sign`, and optionally `CRL Sign` when CRLs are used.

Yubira rejects expired and not-yet-valid certificates locally before requesting the PIN or a signature; IAM Roles Anywhere remains the authoritative certificate-validation boundary. Yubira also validates region syntax, duration, ARN shape and relationships, supported commercial AWS/GovCloud partition mapping, and exact returned `roleArn` binding. Cross-account target roles remain permitted when the partition is coherent. Unsupported partitions fail closed rather than guessing endpoint behavior.

Maintain an inventory that maps certificate serial number, subject, issuer, token custodian, intended role/profile, issuance date, expiration, and revocation status. Define renewal before expiration and immediate revocation for loss, theft, offboarding, custody violations, or suspected CA/key compromise.

IAM Roles Anywhere revocation uses imported CRLs. It does not call certificate distribution points or OCSP endpoints. The PKI process must generate an applicable CRL and import/update it through IAM Roles Anywhere. Test revocation end to end; publishing a CRL only at the CA is insufficient.

If an intermediate CA is used, pass `--certificate-chain` with a PEM bundle ordered from the leaf issuer toward the configured trust anchor. Both implementations enforce the IAM Roles Anywhere maximum depth of five certificates, a 64 KiB input bound, DER parsing, duplicate rejection, and issuer/subject ordering. The chain is encoded as comma-delimited base64 DER in `X-Amz-X509-Chain`, included in canonical signed headers, sent with the request, and redacted from diagnostics. Omit the option for a leaf directly issued by the trust anchor. IAM Roles Anywhere remains responsible for cryptographic chain and trust-anchor validation.

## YubiKey provisioning boundary

PIN and touch policies are selected when the PIV private key is generated or imported and are enforced by the YubiKey PIV implementation. Yubira cannot change those policies or independently guarantee physical presence. Provisioning owners should:

- replace factory PIN, PUK, and management credentials;
- select PIN/touch policies appropriate to the emergency-access procedure;
- prefer on-device key generation where the assurance model requires it;
- retain attestation evidence where supported and required;
- record token serial/certificate identity and custody;
- maintain a replacement and revocation process.


`--serial` remains optional when exactly one YubiKey is connected. If multiple devices are present, Yubira fails closed until an explicit serial is supplied; production credential-process profiles should specify a serial whenever multiple trusted tokens may be attached.

Yubira explicitly verifies the PIN in its own signing path. This does not prevent another local process from invoking PIV directly and must not be represented as hardware-policy enforcement.

## Credential and diagnostic handling

Successful `credential_process` output contains an access key ID, secret access key, and session token. Protect stdout, stderr, process memory, terminal history, shell tracing, support bundles, and AWS client logs accordingly.

Debug diagnostics expose only safe request/response metadata and non-replayable SHA-256 values. They omit credentials, response bodies, certificate material, Authorization data, ARN query values, canonical requests, and strings-to-sign. Regression tests enforce those omissions in both implementations. Continue to protect diagnostic output because operational metadata can still be sensitive.

Python cannot reliably erase immutable strings or all interpreter/allocator/serializer buffers. Prefer the Rust implementation when explicit zeroization of in-process credential fields is part of the threat model. Rust zeroizes owned credential fields and raw response buffers, but neither implementation can erase credentials already written to stdout, operating-system buffers, or the consuming AWS process.

Interactive PIN entry avoids terminal echo. `YUBIKEY_PIV_PIN` remains available for noninteractive credential-process operation. Both implementations consume and remove their own environment entry before verification so it cannot be inherited by later child processes. Rust holds the PIN in `Zeroizing<String>` and drops it immediately after verification; Python deletes its local reference at the same point but cannot scrub immutable strings or runtime copies.

Environment PIN input remains an automation trade-off: removal cannot erase the value in the invoking shell/AWS process, same-user observations or snapshots made before removal, or stale runtime/operating-system storage. Do not place PIN values in shell history, committed configuration, shared CI variables, or long-lived session environments. Unset the caller's copy promptly after the noninteractive operation.

## CloudTrail monitoring

Create a multi-Region trail (or organization trail) with retention suitable for access investigations. Monitor successful and failed IAM Roles Anywhere activity, especially `CreateSession`.

Correlate events using:

- account, Region, source IP address, and event time;
- target role and trust anchor;
- certificate-derived source identity;
- role session name, which IAM Roles Anywhere derives from the certificate serial number;
- expected operator/change/incident context.

For successful `CreateSession`, inspect `additionalEventData`. A conforming request should report:

```json
{
  "missingSignedHeaders": [],
  "postEmptyBody": false,
  "algorithmMismatch": false
}
```

Alert on non-empty `missingSignedHeaders`, `postEmptyBody: true`, `algorithmMismatch: true`, unexpected certificate identities, unexpected roles/accounts/Regions, unusual source networks, disabled/updated trust anchors or profiles, and CRL lifecycle failures.

## Break-glass operating procedure

Before treating Yubira as emergency access, define and exercise a runbook containing:

1. Named service owner and approving authority.
2. Token/certificate custody and inventory.
3. Trigger criteria and authorization for emergency use.
4. A tested command sequence using the dedicated role/profile.
5. Expected CloudTrail evidence and an incident/change identifier.
6. Short session duration and explicit end-of-use review.
7. Immediate lost-token and certificate-revocation steps.
8. Backup access that does not share the same single failure mode.
9. Periodic tests, access reviews, and certificate/CRL expiry checks.
10. Post-use review of actions performed with the issued session.

Do not describe the design as “break glass” solely because the private key is hardware-backed. Emergency access also depends on IAM scope, PKI availability, token custody, revocation, monitoring, recovery, and regularly tested procedures.

## Pre-deployment checklist

- [ ] Dedicated least-privilege role and Roles Anywhere profile
- [ ] Trust restricted by trust-anchor source and certificate identity
- [ ] Cross-account trust reviewed in every target account
- [ ] Session duration minimized and bounded by profile/role
- [ ] End-entity and CA certificate requirements verified
- [ ] Certificate/token inventory and ownership recorded
- [ ] CRL generation, import, refresh, and revocation tested
- [ ] PIV provisioning policy approved by its owning process
- [ ] Credential/PIN logging prohibited
- [ ] CloudTrail trail, retention, and CreateSession detections configured
- [ ] Lost-token, CA-compromise, and break-glass runbooks exercised
- [ ] Backup recovery path tested
- [ ] GitLab security/build controls pass for the exact release

## References

- [IAM Roles Anywhere trust model](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html)
- [IAM Roles Anywhere authentication process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication.html)
- [IAM Roles Anywhere CreateSession API](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html)
- [IAM Roles Anywhere credential helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html)
- [IAM Roles Anywhere CloudTrail logging](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/logging-using-cloudtrail.html)
