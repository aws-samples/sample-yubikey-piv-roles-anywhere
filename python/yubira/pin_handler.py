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
"""PIN handler module for YubiKey PIV PIN management."""

import os
import getpass
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from yubikit.piv import PivSession, SLOT


class PinSource(Enum):
    """Source for PIN retrieval."""
    PROMPT = "prompt"
    ENVIRONMENT = "environment"


class PinError(Exception):
    """Base exception for PIN-related errors."""
    pass


class PinBlockedError(PinError):
    """Raised when the PIN is blocked due to too many failed attempts."""
    pass


class PinRequiredError(PinError):
    """Raised when PIN verification is required but not provided."""
    pass


@dataclass
class PinResult:
    """Result of a PIN verification attempt."""
    success: bool
    retries_remaining: Optional[int] = None
    error_message: Optional[str] = None


class PinHandler:
    """
    Manages PIN entry and verification for YubiKey PIV operations.
    
    Supports PIN retrieval from environment variables or interactive prompt,
    and tracks retry counts for failed verification attempts.
    """
    
    ENV_VAR = "YUBIKEY_PIV_PIN"
    
    def __init__(self, session: PivSession):
        """
        Initialize the PIN handler.
        
        Args:
            session: An active PIV session from a connected YubiKey.
        """
        self._session = session
    
    def get_pin(self, source: PinSource = PinSource.PROMPT) -> str:
        """
        Get PIN from environment or prompt user.
        
        Args:
            source: Where to retrieve the PIN from. If ENVIRONMENT, reads from
                   YUBIKEY_PIV_PIN environment variable. If PROMPT, prompts
                   the user interactively.
                   
        Returns:
            The PIN string.
            
        Raises:
            PinRequiredError: If environment variable is not set when using
                             ENVIRONMENT source.
        """
        if source == PinSource.ENVIRONMENT:
            pin = os.environ.get(self.ENV_VAR)
            if pin is None:
                raise PinRequiredError(
                    f"PIN environment variable {self.ENV_VAR} is not set."
                )
            return pin
        else:
            return getpass.getpass("Enter YubiKey PIV PIN: ")
    
    def get_pin_auto(self) -> tuple[str, PinSource]:
        """
        Get PIN automatically, preferring environment variable over prompt.
        
        Returns:
            Tuple of (pin, source) indicating the PIN and where it came from.
        """
        pin = os.environ.get(self.ENV_VAR)
        if pin is not None:
            return pin, PinSource.ENVIRONMENT
        return getpass.getpass("Enter YubiKey PIV PIN: "), PinSource.PROMPT
    
    def verify_pin(self, pin: str) -> PinResult:
        """
        Verify PIN with YubiKey, return result with retry info.
        
        Args:
            pin: The PIN to verify.
            
        Returns:
            PinResult indicating success/failure and remaining retries.
            
        Raises:
            PinBlockedError: If the PIN is blocked (no retries remaining).
        """
        try:
            self._session.verify_pin(pin)
            return PinResult(success=True)
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check if PIN is blocked
            if "blocked" in error_msg:
                raise PinBlockedError(
                    "PIN is blocked. Use PUK to unblock."
                ) from e
            
            # Try to extract retry count from error message
            retries = self._extract_retries(str(e))
            
            if retries is not None and retries == 0:
                raise PinBlockedError(
                    "PIN is blocked. Use PUK to unblock."
                ) from e
            
            return PinResult(
                success=False,
                retries_remaining=retries,
                error_message=f"Incorrect PIN. {retries} attempts remaining." if retries else "Incorrect PIN."
            )
    
    def get_retries_remaining(self) -> int:
        """
        Get the number of PIN retries remaining.
        
        Returns:
            Number of PIN attempts remaining before lockout.
        """
        try:
            return self._session.get_pin_attempts()
        except Exception:
            # If we can't get the retry count, return -1 to indicate unknown
            return -1
    
    def is_pin_required(self, slot: SLOT) -> bool:
        """
        Check if PIN is required for signing with this slot.
        
        Most PIV operations require PIN verification. This method checks
        if the slot requires PIN for signing operations.
        
        Args:
            slot: The PIV slot to check.
            
        Returns:
            True if PIN is required, False otherwise.
        """
        # For PIV, PIN is generally required for signing operations
        # The Authentication slot (9a) always requires PIN
        # Other slots may have different policies
        return True
    
    @staticmethod
    def _extract_retries(error_message: str) -> Optional[int]:
        """
        Extract retry count from error message.
        
        Args:
            error_message: The error message from a failed PIN verification.
            
        Returns:
            Number of retries remaining, or None if not found.
        """
        import re
        
        # Common patterns for retry count in error messages
        patterns = [
            r'(\d+)\s*(?:retry|retries|attempt|attempts|try|tries)\s*(?:remaining|left)',
            r'(?:retry|retries|attempt|attempts|try|tries)\s*(?:remaining|left)[:\s]*(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, error_message, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
