# Security Policy

## Supported versions

Security fixes are applied to the latest source on the repository's default branch and, when releases are published, the latest release. Older commits, forks, and superseded releases are not supported unless the maintainers explicitly state otherwise.

## Reporting a vulnerability

Report suspected vulnerabilities privately through the [AWS Vulnerability Reporting](https://aws.amazon.com/security/vulnerability-reporting/) process. Do not open a public GitHub issue, discussion, or pull request for a suspected vulnerability.

Include, when available:

- the affected version, release, or commit;
- a description of the issue and its security impact;
- minimal reproduction steps or a proof of concept;
- relevant configuration and platform details;
- suggested mitigations or fixes; and
- a safe way to contact you for follow-up.

Do not include active AWS credentials, PIV PINs, private keys, or other production secrets. Use synthetic values and redact logs. If sensitive evidence is necessary, wait for instructions from the AWS vulnerability-response team before transmitting it.

## Response and coordinated disclosure

Reports are acknowledged, triaged, and coordinated through the AWS Vulnerability Reporting process. Response timing depends on severity and investigation complexity; this repository does not promise a fixed remediation deadline. Maintainers will coordinate validation, remediation, release communication, and any security advisory with the reporting process.

Keep the report confidential until AWS and the maintainers confirm that disclosure is safe or agree on a disclosure date. After sensitive details have been addressed, ordinary non-sensitive follow-up may move to the public issue tracker.

## Scope

Relevant reports include vulnerabilities in the Python or Rust credential helper, IAM Roles Anywhere request construction, credential/PIN handling, certificate validation, YubiKey interaction, dependency use, and release artifacts. Security defects in AWS services or other AWS products should use the same AWS reporting process and identify the affected service or product.
