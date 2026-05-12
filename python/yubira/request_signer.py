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
"""Request signer module for IAM Roles Anywhere authentication requests."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional
from urllib.parse import quote
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from yubikit.piv import PivSession, SLOT, KEY_TYPE


class SigningError(Exception):
    """Raised when signing operation fails."""
    pass


class InvalidRequestError(Exception):
    """Raised when request parameters are invalid."""
    pass


@dataclass
class SignedRequest:
    """A signed HTTP request ready to be sent."""
    method: str
    uri: str
    headers: dict[str, str]
    body: bytes
    signature: bytes


SignatureAlgorithm = Literal[
    "RSA-SHA256", 
    "ECDSA-SHA256", 
]


class RequestSigner:
    """
    Creates and signs IAM Roles Anywhere authentication requests.
    
    Implements AWS SigV4 signing with X.509 certificates, using the YubiKey
    to perform cryptographic signing operations without exposing private keys.
    """
    
    SERVICE = "rolesanywhere"
    ALGORITHM_PREFIX = "AWS4-X509"
    
    def __init__(self, session: PivSession, slot: SLOT = SLOT.AUTHENTICATION):
        """
        Initialize the request signer.
        
        Args:
            session: An active PIV session from a connected YubiKey.
            slot: PIV slot containing the signing key. Defaults to AUTHENTICATION (9a).
        """
        self._session = session
        self._slot = slot
        self._key_type: Optional[KEY_TYPE] = None
        self._cached_algorithm: Optional[SignatureAlgorithm] = None
    
    def get_signature_algorithm(self) -> SignatureAlgorithm:
        """
        Determine signature algorithm based on key type in slot.
        
        Returns:
            The signature algorithm string (e.g., "SHA256withRSA", "SHA256withECDSA").
            
        Raises:
            SigningError: If the key type cannot be determined or is unsupported.
        """
        if self._cached_algorithm is not None:
            return self._cached_algorithm
        
        try:
            # Get the certificate to determine key type
            cert = self._session.get_certificate(self._slot)
            if cert is None:
                raise SigningError(f"No certificate found in slot {self._slot}")
            
            public_key = cert.public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                self._cached_algorithm = "RSA-SHA256"
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # IAM Roles Anywhere only accepts SHA256 digests, even for P-384 keys.
                # The signing algorithm is always ECDSA-SHA256 regardless of curve size.
                self._cached_algorithm = "ECDSA-SHA256"
            else:
                raise SigningError(f"Unsupported key type: {type(public_key)}")
            
            return self._cached_algorithm
            
        except SigningError:
            raise
        except Exception as e:
            raise SigningError(f"Failed to determine signature algorithm: {e}") from e

    def create_canonical_request(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: dict[str, str],
        payload_hash: str
    ) -> str:
        """
        Create canonical request string per AWS SigV4 spec.
        
        The canonical request format is:
        HTTPRequestMethod + '\n' +
        CanonicalURI + '\n' +
        CanonicalQueryString + '\n' +
        CanonicalHeaders + '\n' +
        SignedHeaders + '\n' +
        HashedPayload
        
        Args:
            method: HTTP method (GET, POST, etc.) - will be uppercased.
            uri: URI path (e.g., "/sessions").
            query_string: Query string without leading '?' (can be empty).
            headers: Dictionary of header names to values.
            payload_hash: SHA-256 hash of the request payload (hex-encoded).
            
        Returns:
            The canonical request string.
        """
        # 1. HTTP method (uppercase)
        canonical_method = method.upper()
        
        # 2. Canonical URI (URI-encoded path)
        canonical_uri = self._uri_encode_path(uri)
        
        # 3. Canonical query string (sorted by parameter name)
        canonical_query = self._create_canonical_query_string(query_string)
        
        # 4. Canonical headers (sorted, lowercase names, trimmed values)
        canonical_headers, signed_headers = self._create_canonical_headers(headers)
        
        # 5. Combine all parts
        canonical_request = "\n".join([
            canonical_method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        ])
        
        return canonical_request
    
    def _uri_encode_path(self, uri: str) -> str:
        """
        URI-encode the path component.
        
        Args:
            uri: The URI path to encode.
            
        Returns:
            URI-encoded path with '/' preserved.
        """
        if not uri:
            return "/"
        
        # Normalize path - ensure it starts with /
        if not uri.startswith("/"):
            uri = "/" + uri
        
        # URI-encode each path segment, preserving '/'
        segments = uri.split("/")
        encoded_segments = []
        for segment in segments:
            if segment:
                # Use quote with safe='' to encode everything except unreserved chars
                encoded_segments.append(quote(segment, safe="-_.~"))
            else:
                encoded_segments.append("")
        
        return "/".join(encoded_segments) or "/"
    
    def _create_canonical_query_string(self, query_string: str) -> str:
        """
        Create canonical query string (sorted by parameter name).
        
        The query string is expected to already be URL-encoded.
        This function sorts the parameters but does NOT re-encode them.
        
        Args:
            query_string: URL-encoded query string without leading '?'.
            
        Returns:
            Canonical query string with sorted parameters.
        """
        if not query_string:
            return ""
        
        # Parse query parameters (already URL-encoded)
        params = []
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
            else:
                key, value = param, ""
            params.append((key, value))
        
        # Sort by key, then by value (lexicographically on encoded values)
        params.sort(key=lambda x: (x[0], x[1]))
        
        return "&".join(f"{k}={v}" for k, v in params)
    
    def _create_canonical_headers(self, headers: dict[str, str]) -> tuple[str, str]:
        """
        Create canonical headers and signed headers string.
        
        Args:
            headers: Dictionary of header names to values.
            
        Returns:
            Tuple of (canonical_headers, signed_headers).
            canonical_headers: Sorted headers with lowercase names and trimmed values.
            signed_headers: Semicolon-separated list of lowercase header names.
        """
        # Convert to lowercase keys and trim values
        normalized = {}
        for name, value in headers.items():
            lower_name = name.lower()
            # Trim leading/trailing whitespace and collapse internal whitespace
            trimmed_value = " ".join(value.split())
            normalized[lower_name] = trimmed_value
        
        # Sort by header name
        sorted_names = sorted(normalized.keys())
        
        # Build canonical headers (each header ends with newline)
        canonical_lines = []
        for name in sorted_names:
            canonical_lines.append(f"{name}:{normalized[name]}")
        canonical_headers = "\n".join(canonical_lines) + "\n"
        
        # Build signed headers
        signed_headers = ";".join(sorted_names)
        
        return canonical_headers, signed_headers

    def create_string_to_sign(
        self,
        timestamp: datetime,
        region: str,
        canonical_request: str
    ) -> str:
        """
        Create string to sign per IAM Roles Anywhere spec.
        
        The string to sign format is:
        Algorithm + '\n' +
        RequestDateTime + '\n' +
        CredentialScope + '\n' +
        HashedCanonicalRequest
        
        Args:
            timestamp: Request timestamp (UTC).
            region: AWS region (e.g., "us-east-1").
            canonical_request: The canonical request string.
            
        Returns:
            The string to sign.
        """
        # Get algorithm
        algorithm = f"{self.ALGORITHM_PREFIX}-{self.get_signature_algorithm()}"
        
        # Format timestamp as ISO8601 basic format
        request_datetime = timestamp.strftime("%Y%m%dT%H%M%SZ")
        
        # Create credential scope
        date_stamp = timestamp.strftime("%Y%m%d")
        credential_scope = f"{date_stamp}/{region}/{self.SERVICE}/aws4_request"
        
        # Hash the canonical request
        hashed_canonical = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        
        # Combine all parts
        string_to_sign = "\n".join([
            algorithm,
            request_datetime,
            credential_scope,
            hashed_canonical
        ])
        
        return string_to_sign
    
    def sign(self, data: bytes) -> bytes:
        """
        Sign data using YubiKey private key.
        
        PIN must be verified before calling this method.
        
        Args:
            data: The data to sign.
            
        Returns:
            The signature bytes.
            
        Raises:
            SigningError: If signing fails.
        """
        try:
            algorithm = self.get_signature_algorithm()
            
            # IAM Roles Anywhere requires SHA256 for all key types
            hash_alg = hashes.SHA256()
            
            # Get the slot's metadata to determine key type
            cert = self._session.get_certificate(self._slot)
            public_key = cert.public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                # RSA signing with PKCS#1 v1.5 padding
                signature = self._session.sign(
                    self._slot,
                    KEY_TYPE.RSA2048,  # Will be determined by actual key
                    data,
                    hash_alg,
                    padding.PKCS1v15()
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # ECDSA signing
                curve_name = public_key.curve.name
                if curve_name in ("secp384r1", "prime384v1"):
                    key_type = KEY_TYPE.ECCP384
                else:
                    key_type = KEY_TYPE.ECCP256
                
                signature = self._session.sign(
                    self._slot,
                    key_type,
                    data,
                    hash_alg,
                )
            else:
                raise SigningError(f"Unsupported key type: {type(public_key)}")
            
            return signature
            
        except SigningError:
            raise
        except Exception as e:
            raise SigningError(f"Signing failed: {e}") from e
    
    def sign_request(
        self,
        method: str,
        uri: str,
        headers: dict[str, str],
        body: bytes,
        region: str,
        timestamp: datetime,
        query_string: str = ""
    ) -> SignedRequest:
        """
        Create and sign a complete request.
        
        This method:
        1. Computes the payload hash
        2. Creates the canonical request
        3. Creates the string to sign
        4. Signs the string using the YubiKey
        5. Returns a SignedRequest with all headers including Authorization
        
        Args:
            method: HTTP method.
            uri: Request URI path.
            headers: Request headers (should include Host, Content-Type, X-Amz-Date).
            body: Request body bytes.
            region: AWS region.
            timestamp: Request timestamp (UTC).
            query_string: Query string without leading '?' (default empty).
            
        Returns:
            SignedRequest with signature and updated headers.
            
        Raises:
            SigningError: If signing fails.
        """
        # Compute payload hash
        payload_hash = hashlib.sha256(body).hexdigest()
        
        # Copy headers (don't add x-amz-content-sha256 - not needed for Roles Anywhere)
        request_headers = dict(headers)
        
        # Create canonical request (with query string)
        canonical_request = self.create_canonical_request(
            method=method,
            uri=uri,
            query_string=query_string,
            headers=request_headers,
            payload_hash=payload_hash
        )
        
        # Create string to sign
        string_to_sign = self.create_string_to_sign(
            timestamp=timestamp,
            region=region,
            canonical_request=canonical_request
        )
        
        # Sign the string
        signature = self.sign(string_to_sign.encode("utf-8"))
        
        # Create Authorization header
        algorithm = f"{self.ALGORITHM_PREFIX}-{self.get_signature_algorithm()}"
        date_stamp = timestamp.strftime("%Y%m%d")
        credential_scope = f"{date_stamp}/{region}/{self.SERVICE}/aws4_request"
        
        # Get signed headers list
        _, signed_headers = self._create_canonical_headers(request_headers)
        
        # Get certificate serial for credential (decimal string, not hex)
        cert = self._session.get_certificate(self._slot)
        cert_serial = str(cert.serial_number)
        
        authorization = (
            f"{algorithm} "
            f"Credential={cert_serial}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature.hex()}"
        )
        
        request_headers["Authorization"] = authorization
        
        return SignedRequest(
            method=method,
            uri=uri,
            headers=request_headers,
            body=body,
            signature=signature
        )
    
    @staticmethod
    def hash_payload(payload: bytes) -> str:
        """
        Compute SHA-256 hash of payload.
        
        Args:
            payload: The payload bytes to hash.
            
        Returns:
            Hex-encoded SHA-256 hash.
        """
        return hashlib.sha256(payload).hexdigest()
