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
"""
YubiKey IAM Roles Anywhere credential process CLI.

This module provides the command-line interface entry point.
"""

import argparse
from yubira.input_validation import ConfigurationError, validate_configuration
from yubira.certificate_chain import CertificateChainError, load_certificate_chain
import json
import sys
from typing import NoReturn

from yubira import (
    YubiKeyConnector,
    YubiKeyConnectionError,
    MultipleYubiKeysError,
    YubiKeyNotFoundError,
    CertificateReader,
    CertificateNotFoundError,
    CertificateReadError,
    parse_slot,
    PinHandler,
    PinSource,
    PinBlockedError,
    PinRequiredError,
    RequestSigner,
    SigningError,
    RolesAnywhereClient,
    RolesAnywhereAPIError,
    RolesAnywhereNetworkError,
)


# Exit codes as defined in design document
EXIT_SUCCESS = 0
EXIT_NO_DEVICE = 1
EXIT_CONNECTION_FAILED = 2
EXIT_NO_CERTIFICATE = 3
EXIT_PIN_ERROR = 4
EXIT_CERTIFICATE_EXPIRED = 5
EXIT_API_ERROR = 6
EXIT_NETWORK_ERROR = 7


def error_exit(message: str, exit_code: int) -> NoReturn:
    """
    Print error message to stderr and exit with specified code.
    
    Args:
        message: Error message to display.
        exit_code: Exit code to return.
    """
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(exit_code)


def init_argparse() -> argparse.ArgumentParser:
    """
    Initialize and return the argument parser.
    
    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="yubira",
        description="Get AWS credentials using YubiKey certificate via IAM Roles Anywhere",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc \\
           --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/def \\
           --role-arn arn:aws:iam::123456789012:role/MyRole

  %(prog)s --trust-anchor-arn <ARN> --profile-arn <ARN> --role-arn <ARN> --slot 9c

Environment Variables:
  YUBIKEY_PIV_PIN    If set, use this PIN instead of prompting
"""
    )
    
    parser.add_argument(
        "--trust-anchor-arn",
        required=True,
        help="ARN of the IAM Roles Anywhere trust anchor"
    )
    
    parser.add_argument(
        "--profile-arn",
        required=True,
        help="ARN of the IAM Roles Anywhere profile"
    )
    
    parser.add_argument(
        "--role-arn",
        required=True,
        help="ARN of the IAM role to assume"
    )
    
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    
    parser.add_argument(
        "--slot",
        default="9a",
        help="PIV slot containing the certificate (default: 9a)"
    )
    
    parser.add_argument(
        "--serial",
        type=int,
        help="YubiKey serial number (if multiple devices connected)"
    )

    parser.add_argument(
        "--certificate-chain",
        help=(
            "Optional PEM bundle of up to five intermediates, ordered from "
            "the leaf issuer toward the trust anchor"
        ),
    )
    
    parser.add_argument(
        "--session-duration",
        type=int,
        default=3600,
        help="Session duration in seconds (default: 3600)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable redacted debug diagnostics (never prints credentials or signed requests)"
    )
    
    return parser


def main() -> int:
    """
    Main entry point for the credential process.
    
    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    parser = init_argparse()
    args = parser.parse_args()
    
    # Parse the slot argument
    try:
        slot = parse_slot(args.slot)
    except ValueError as e:
        error_exit(str(e), EXIT_NO_CERTIFICATE)
    
    try:
        validate_configuration(
            args.trust_anchor_arn,
            args.profile_arn,
            args.role_arn,
            args.region,
            args.session_duration,
        )
    except ConfigurationError as exc:
        error_exit(f"Invalid configuration: {exc}", EXIT_API_ERROR)

    # Connect to YubiKey
    connector = YubiKeyConnector(serial=args.serial)
    
    try:
        connector.connect()
    except YubiKeyNotFoundError as e:
        if args.serial:
            error_exit(f"YubiKey with serial {args.serial} not found.", EXIT_NO_DEVICE)
        else:
            error_exit("No YubiKey detected. Please insert a YubiKey.", EXIT_NO_DEVICE)
    except MultipleYubiKeysError:
        error_exit(
            "Multiple YubiKeys detected. Specify --serial.",
            EXIT_CONNECTION_FAILED,
        )
    except YubiKeyConnectionError:
        error_exit("Failed to connect to YubiKey.", EXIT_CONNECTION_FAILED)
    
    try:
        # Get PIV session
        session = connector.get_piv_session()
        
        # Read certificate from slot
        cert_reader = CertificateReader(session)
        try:
            cert_info = cert_reader.read_certificate(slot)
        except CertificateNotFoundError:
            slot_name = args.slot.lower()
            error_exit(f"No certificate found in slot {slot_name}.", EXIT_NO_CERTIFICATE)
        except CertificateReadError:
            error_exit("Failed to read certificate.", EXIT_NO_CERTIFICATE)
        
        # Check if certificate is expired
        # nosemgrep: is-function-without-parentheses
        if cert_info.is_expired is True:
            error_exit(
                f"Certificate expired on {cert_info.not_after.strftime('%Y-%m-%d')}.",
                EXIT_CERTIFICATE_EXPIRED
            )
        # nosemgrep: is-function-without-parentheses
        if cert_info.is_not_yet_valid is True:
            error_exit(
                f"Certificate is not valid before "
                f"{cert_info.not_before.strftime('%Y-%m-%d')}.",
                EXIT_CERTIFICATE_EXPIRED,
            )

        certificate_chain_der = None
        if args.certificate_chain:
            try:
                certificate_chain_der = load_certificate_chain(
                    args.certificate_chain,
                    cert_info.to_der(),
                )
            except CertificateChainError as exc:
                error_exit(f"Invalid certificate chain: {exc}", EXIT_NO_CERTIFICATE)
        
        # Handle PIN verification
        pin_handler = PinHandler(session)
        
        if pin_handler.is_pin_required(slot):
            try:
                pin, _source = pin_handler.get_pin_auto()
            except PinRequiredError:
                error_exit("PIN verification required.", EXIT_PIN_ERROR)

            try:
                result = pin_handler.verify_pin(pin)
            finally:
                # Minimize lifetime; Python cannot reliably scrub immutable str.
                del pin
            
            if not result.success:
                if result.retries_remaining is not None:
                    error_exit(
                        f"Incorrect PIN. {result.retries_remaining} attempts remaining.",
                        EXIT_PIN_ERROR
                    )
                else:
                    error_exit("Incorrect PIN.", EXIT_PIN_ERROR)
        
        # Create request signer
        signer = RequestSigner(session, slot)
        
        # Create Roles Anywhere client
        client = RolesAnywhereClient(
            trust_anchor_arn=args.trust_anchor_arn,
            profile_arn=args.profile_arn,
            role_arn=args.role_arn,
            region=args.region,
            session_duration=args.session_duration
        )
        
        # Get credentials
        try:
            credentials = client.create_session(
                certificate_der=cert_info.to_der(),
                signer=signer,
                certificate_chain_der=certificate_chain_der,
                debug=args.debug
            )
        except SigningError:
            error_exit("Signing failed.", EXIT_API_ERROR)
        except RolesAnywhereAPIError:
            error_exit("CreateSession request failed.", EXIT_API_ERROR)
        except RolesAnywhereNetworkError:
            error_exit("Network request failed.", EXIT_NETWORK_ERROR)
        
        # Stream credential JSON directly to stdout without logging or creating
        # an additional aggregate formatted string.
        output = credentials.to_credential_process_output()
        json.dump(output, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        
        return EXIT_SUCCESS
        
    except PinBlockedError:
        error_exit("PIN is blocked. Use PUK to unblock.", EXIT_PIN_ERROR)
    except Exception:
        # Keep arbitrary library/device details out of credential-process stderr.
        error_exit("Unexpected internal error.", EXIT_API_ERROR)
    finally:
        connector.close()


if __name__ == "__main__":
    sys.exit(main())
