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
"""Roles Anywhere client module for obtaining AWS credentials via IAM Roles Anywhere."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import base64
import hashlib
import json
import sys

import requests

from .certificate_chain import encode_certificate_chain, validate_certificate_chain
from .input_validation import validate_configuration
from .request_signer import RequestSigner, SigningError


class RolesAnywhereError(Exception):
    """Base exception for Roles Anywhere client errors."""
    pass


class RolesAnywhereAPIError(RolesAnywhereError):
    """Raised when the CreateSession API returns an error."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class RolesAnywhereNetworkError(RolesAnywhereError):
    """Raised when a network error occurs."""
    pass


@dataclass
class AWSCredentials:
    """AWS temporary credentials returned by IAM Roles Anywhere."""
    
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expiration: datetime
    
    def to_credential_process_output(self) -> dict:
        """
        Format credentials for AWS CLI credential_process.
        
        Returns:
            Dictionary with Version, AccessKeyId, SecretAccessKey,
            SessionToken, and Expiration fields as expected by AWS CLI.
        """
        return {
            "Version": 1,
            "AccessKeyId": self.access_key_id,
            "SecretAccessKey": self.secret_access_key,
            "SessionToken": self.session_token,
            "Expiration": self.expiration.isoformat().replace("+00:00", "Z")
        }


class RolesAnywhereClient:
    """
    Client for IAM Roles Anywhere CreateSession API.
    
    This client handles the construction and signing of requests to the
    IAM Roles Anywhere service to obtain temporary AWS credentials using
    X.509 certificates stored on a YubiKey.
    """
    
    SERVICE = "rolesanywhere"
    API_PATH = "/sessions"
    
    def __init__(
        self,
        trust_anchor_arn: str,
        profile_arn: str,
        role_arn: str,
        region: str = "us-east-1",
        session_duration: int = 3600
    ):
        """
        Initialize the Roles Anywhere client.
        
        Args:
            trust_anchor_arn: ARN of the IAM Roles Anywhere trust anchor.
            profile_arn: ARN of the IAM Roles Anywhere profile.
            role_arn: ARN of the IAM role to assume.
            region: AWS region for the Roles Anywhere endpoint.
            session_duration: Duration in seconds for the session (default 3600).
        """
        validate_configuration(
            trust_anchor_arn,
            profile_arn,
            role_arn,
            region,
            session_duration,
        )
        self._trust_anchor_arn = trust_anchor_arn
        self._profile_arn = profile_arn
        self._role_arn = role_arn
        self._region = region
        self._session_duration = session_duration

    @property
    def endpoint(self) -> str:
        """Get the Roles Anywhere API endpoint URL."""
        return f"https://{self.SERVICE}.{self._region}.amazonaws.com"
    
    @property
    def host(self) -> str:
        """Get the host header value."""
        return f"{self.SERVICE}.{self._region}.amazonaws.com"
    
    def _build_query_string(self) -> str:
        """
        Build the query string with ARN parameters.
        
        The ARNs are passed as query parameters per the IAM Roles Anywhere API spec.
        
        Returns:
            URL-encoded query string.
        """
        from urllib.parse import quote
        
        params = [
            f"profileArn={quote(self._profile_arn, safe='')}",
            f"roleArn={quote(self._role_arn, safe='')}",
            f"trustAnchorArn={quote(self._trust_anchor_arn, safe='')}"
        ]
        return "&".join(params)
    
    def _build_request_body(self) -> dict:
        """
        Build the CreateSession request body.
        
        Returns:
            Dictionary containing the session duration.
        """
        return {
            "durationSeconds": self._session_duration
        }
    
    def _build_headers(
        self,
        certificate_der: bytes,
        timestamp: datetime,
        content_length: int,
        certificate_chain_der: tuple[bytes, ...] | None = None,
    ) -> dict[str, str]:
        """
        Build the request headers.
        
        Args:
            certificate_der: DER-encoded X.509 certificate.
            timestamp: Request timestamp (UTC).
            content_length: Length of the request body.
            
        Returns:
            Dictionary of header names to values.
        """
        # Base64 encode the certificate
        cert_b64 = base64.b64encode(certificate_der).decode("ascii")
        
        # Format timestamp as ISO8601 basic format
        amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
        
        headers = {
            "Host": self.host,
            "Content-Type": "application/json",
            "X-Amz-Date": amz_date,
            "X-Amz-X509": cert_b64,
            "Content-Length": str(content_length)
        }
        if certificate_chain_der is not None:
            validated_chain = validate_certificate_chain(
                certificate_der,
                certificate_chain_der,
            )
            headers["X-Amz-X509-Chain"] = encode_certificate_chain(validated_chain)
        return headers
    
    def _parse_response(self, response: requests.Response) -> AWSCredentials:
        """
        Parse the CreateSession API response.
        
        Args:
            response: HTTP response from the API.
            
        Returns:
            AWSCredentials object with the temporary credentials.
            
        Raises:
            RolesAnywhereAPIError: If the response indicates an error.
        """
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise RolesAnywhereAPIError(
                f"Invalid JSON response: {e}",
                status_code=response.status_code
            ) from e
        
        # Check for error response
        if response.status_code not in (200, 201):
            error_message = data.get("message", data.get("Message", "Unknown error"))
            error_code = data.get("code", data.get("Code"))
            raise RolesAnywhereAPIError(
                f"CreateSession failed: {error_message}",
                status_code=response.status_code,
                error_code=error_code
            )
        
        # Extract credentials from response
        # Response format: {"credentialSet": [{"credentials": {...}, ...}]}
        try:
            credential_set = data.get("credentialSet", [])
            if not credential_set:
                raise RolesAnywhereAPIError(
                    "No credentials returned in response",
                    status_code=response.status_code
                )
            
            entry = credential_set[0]
            if entry.get("roleArn") != self._role_arn:
                raise RolesAnywhereAPIError(
                    "Returned role does not match requested role",
                    status_code=response.status_code,
                )

            creds = entry.get("credentials", {})
            
            access_key_id = creds.get("accessKeyId")
            secret_access_key = creds.get("secretAccessKey")
            session_token = creds.get("sessionToken")
            expiration_str = creds.get("expiration")
            
            if not all([access_key_id, secret_access_key, session_token, expiration_str]):
                raise RolesAnywhereAPIError(
                    "Incomplete credentials in response",
                    status_code=response.status_code
                )
            
            # Parse expiration timestamp
            # Format: "2024-01-15T12:00:00Z"
            expiration = datetime.fromisoformat(
                expiration_str.replace("Z", "+00:00")
            )
            
            return AWSCredentials(
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                session_token=session_token,
                expiration=expiration
            )
            
        except KeyError as e:
            raise RolesAnywhereAPIError(
                f"Missing field in response: {e}",
                status_code=response.status_code
            ) from e

    def create_session(
        self,
        certificate_der: bytes,
        signer: RequestSigner,
        debug: bool = False,
        certificate_chain_der: tuple[bytes, ...] | None = None,
    ) -> AWSCredentials:
        """
        Call CreateSession API with signed request.
        
        This method:
        1. Builds the request body and headers
        2. Signs the request using the provided signer
        3. Sends the request to the Roles Anywhere API
        4. Parses and returns the credentials
        
        Args:
            certificate_der: DER-encoded X.509 certificate.
            signer: RequestSigner configured with the YubiKey session.
            debug: If True, print request details to stderr.
            
        Returns:
            AWSCredentials containing temporary AWS credentials.
            
        Raises:
            RolesAnywhereAPIError: If the API returns an error.
            RolesAnywhereNetworkError: If a network error occurs.
            SigningError: If signing the request fails.
        """
        # Get current timestamp in UTC
        timestamp = datetime.now(timezone.utc)
        
        # Build request body (just durationSeconds)
        body_dict = self._build_request_body()
        body = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
        
        # Build query string with ARNs
        query_string = self._build_query_string()
        
        # Build initial headers
        headers = self._build_headers(
            certificate_der=certificate_der,
            timestamp=timestamp,
            content_length=len(body),
            certificate_chain_der=certificate_chain_der,
        )
        
        # Sign the request (with query string)
        signed_request = signer.sign_request(
            method="POST",
            uri=self.API_PATH,
            query_string=query_string,
            headers=headers,
            body=body,
            region=self._region,
            timestamp=timestamp
        )
        
        # Send the request (include query string in URL)
        url = f"{self.endpoint}{self.API_PATH}?{query_string}"
        
        # Debug output
        if debug:
            self._print_debug(url, signed_request.headers, body, signer, timestamp)
        
        try:
            # nosemgrep: use-raise-for-status
            response = requests.post(
                url,
                headers=signed_request.headers,
                data=body,
                timeout=30
            )
            
            # Debug response without credential-bearing headers or body.
            if debug:
                self._print_response_debug(response)
            
            # Note: We don't use raise_for_status() because _parse_response
            # handles error status codes with custom error messages from the API response
        except requests.exceptions.Timeout as e:
            raise RolesAnywhereNetworkError(
                f"Request timed out: {e}"
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise RolesAnywhereNetworkError(
                f"Connection error: {e}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise RolesAnywhereNetworkError(
                f"Network error: {e}"
            ) from e
        
        # Parse and return credentials
        return self._parse_response(response)
    
    def _print_debug(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        signer: RequestSigner,
        timestamp: datetime
    ) -> None:
        """Print diagnostics without credential or replayable request material."""
        base_url = url.partition("?")[0]
        print("\n=== DEBUG: REDACTED REQUEST DETAILS ===", file=sys.stderr)
        print(f"URL: {base_url}?<redacted>", file=sys.stderr)
        print("Method: POST", file=sys.stderr)
        print(f"Timestamp: {timestamp.isoformat()}", file=sys.stderr)
        print("\n--- Headers ---", file=sys.stderr)
        safe_headers = {"host", "content-type", "x-amz-date", "content-length"}
        for name, value in sorted(headers.items()):
            if name.lower() in safe_headers:
                print(f"{name}: {value}", file=sys.stderr)
            else:
                print(f"{name}: <redacted>", file=sys.stderr)

        payload_hash = hashlib.sha256(body).hexdigest()
        headers_for_canonical = {
            key: value
            for key, value in headers.items()
            if key.lower() != "authorization"
        }
        canonical_request = signer.create_canonical_request(
            method="POST",
            uri=self.API_PATH,
            query_string=self._build_query_string(),
            headers=headers_for_canonical,
            payload_hash=payload_hash
        )
        string_to_sign = signer.create_string_to_sign(
            timestamp=timestamp,
            region=self._region,
            canonical_request=canonical_request
        )

        print(f"Payload SHA-256: {payload_hash}", file=sys.stderr)
        print(
            "Canonical request SHA-256: "
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}",
            file=sys.stderr,
        )
        print(
            "String-to-sign SHA-256: "
            f"{hashlib.sha256(string_to_sign.encode('utf-8')).hexdigest()}",
            file=sys.stderr,
        )
        print("Sensitive request fields and response bodies are omitted.", file=sys.stderr)
        print("=======================================\n", file=sys.stderr)

    @staticmethod
    def _print_response_debug(response: requests.Response) -> None:
        """Print safe response metadata while always omitting the body."""
        request_id = (
            response.headers.get("x-amzn-requestid")
            or response.headers.get("x-amz-request-id")
            or "<unavailable>"
        )
        content_type = response.headers.get("content-type", "<unavailable>")
        print("\n=== DEBUG: REDACTED RESPONSE ===", file=sys.stderr)
        print(f"Status: {response.status_code}", file=sys.stderr)
        print(f"Request ID: {request_id}", file=sys.stderr)
        print(f"Content-Type: {content_type}", file=sys.stderr)
        print("Body: <redacted>", file=sys.stderr)
        print("================================\n", file=sys.stderr)
