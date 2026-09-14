"""
MIT No Attribution
Copyright 2026 AWS

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
"""YubiKey IAM Roles Anywhere credential process."""

__version__ = "0.1.0"

from yubira.yubikey_connector import (
    YubiKeyConnector,
    YubiKeyInfo,
    YubiKeyConnectionError,
    MultipleYubiKeysError,
    YubiKeyNotFoundError,
)

from yubira.certificate_reader import (
    CertificateReader,
    CertificateInfo,
    CertificateNotFoundError,
    CertificateReadError,
    parse_slot,
    SLOT_MAP,
    ALL_CERTIFICATE_SLOTS,
)

from yubira.pin_handler import (
    PinHandler,
    PinResult,
    PinSource,
    PinError,
    PinBlockedError,
    PinRequiredError,
)

from yubira.request_signer import (
    RequestSigner,
    SignedRequest,
    SignatureAlgorithm,
    SigningError,
    InvalidRequestError,
)

from yubira.roles_anywhere_client import (
    RolesAnywhereClient,
    AWSCredentials,
    RolesAnywhereError,
    RolesAnywhereAPIError,
    RolesAnywhereNetworkError,
)

__all__ = [
    "YubiKeyConnector",
    "YubiKeyInfo",
    "YubiKeyConnectionError",
    "MultipleYubiKeysError",
    "YubiKeyNotFoundError",
    "CertificateReader",
    "CertificateInfo",
    "CertificateNotFoundError",
    "CertificateReadError",
    "parse_slot",
    "SLOT_MAP",
    "ALL_CERTIFICATE_SLOTS",
    "PinHandler",
    "PinResult",
    "PinSource",
    "PinError",
    "PinBlockedError",
    "PinRequiredError",
    "RequestSigner",
    "SignedRequest",
    "SignatureAlgorithm",
    "SigningError",
    "InvalidRequestError",
    "RolesAnywhereClient",
    "AWSCredentials",
    "RolesAnywhereError",
    "RolesAnywhereAPIError",
    "RolesAnywhereNetworkError",
]
