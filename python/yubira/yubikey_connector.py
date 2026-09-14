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
"""YubiKey connector module for device detection and connection management."""

from dataclasses import dataclass
from typing import Optional, List

from yubikit.piv import PivSession
from ykman.device import list_all_devices, SmartCardConnection


@dataclass
class YubiKeyInfo:
    """Information about a connected YubiKey device."""
    serial: int
    version: tuple[int, int, int]


class YubiKeyConnectionError(Exception):
    """Raised when connection to YubiKey fails."""
    pass


class MultipleYubiKeysError(YubiKeyConnectionError):
    """Raised when optional serial selection is ambiguous."""
    pass


class YubiKeyNotFoundError(Exception):
    """Raised when no YubiKey is detected or specified serial not found."""
    pass


class YubiKeyConnector:
    """
    Handles YubiKey device detection and connection management.
    
    Supports optional serial number filtering when multiple YubiKeys are connected.
    Implements context manager protocol for safe resource management.
    """
    
    def __init__(self, serial: Optional[int] = None):
        """
        Initialize connector, optionally targeting specific serial number.
        
        Args:
            serial: Optional YubiKey serial number to connect to. If omitted,
                    connects only when exactly one device is available.
        """
        self._serial = serial
        self._connection: Optional[SmartCardConnection] = None
        self._session: Optional[PivSession] = None
        self._device_info: Optional[YubiKeyInfo] = None
    
    @staticmethod
    def list_devices() -> List[YubiKeyInfo]:
        """
        List all connected YubiKey devices.
        
        Returns:
            List of YubiKeyInfo objects for each detected device.
        """
        devices = []
        for device, info in list_all_devices():
            if info.serial is not None:
                devices.append(YubiKeyInfo(
                    serial=info.serial,
                    version=info.version
                ))
        return devices
    
    def connect(self) -> YubiKeyInfo:
        """
        Connect to YubiKey and return device info.
        
        Returns:
            YubiKeyInfo with serial number and firmware version.
            
        Raises:
            YubiKeyNotFoundError: If no YubiKey is detected or specified serial not found.
            YubiKeyConnectionError: If connection to the device fails.
        """
        try:
            all_devices = list(list_all_devices())
            
            if not all_devices:
                raise YubiKeyNotFoundError("No YubiKey detected. Please insert a YubiKey.")
            
            # Find device matching serial number if specified
            target_device = None
            target_info = None
            
            if self._serial is not None:
                for device, info in all_devices:
                    if info.serial == self._serial:
                        target_device = device
                        target_info = info
                        break
                
                if target_device is None:
                    raise YubiKeyNotFoundError(
                        f"YubiKey with serial {self._serial} not found."
                    )
            else:
                if len(all_devices) > 1:
                    raise MultipleYubiKeysError(
                        "Multiple YubiKeys detected. Specify --serial."
                    )
                target_device, target_info = all_devices[0]
            
            # Connect to the device
            connection = target_device.open_connection(SmartCardConnection)
            self._connection = connection
            
            self._device_info = YubiKeyInfo(
                serial=target_info.serial,
                version=target_info.version
            )
            
            return self._device_info
            
        except (YubiKeyNotFoundError, MultipleYubiKeysError):
            raise
        except Exception as e:
            raise YubiKeyConnectionError(f"Failed to connect to YubiKey: {e}") from e
    
    def get_piv_session(self) -> PivSession:
        """
        Get PIV session for certificate/signing operations.
        
        Returns:
            PivSession instance for PIV operations.
            
        Raises:
            YubiKeyConnectionError: If not connected to a YubiKey.
        """
        if self._connection is None:
            raise YubiKeyConnectionError("Not connected to YubiKey. Call connect() first.")
        
        if self._session is None:
            self._session = PivSession(self._connection)
        
        return self._session
    
    def close(self) -> None:
        """Close connection to YubiKey."""
        self._session = None
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass  # nosec B110 - Ignore errors during cleanup (intentional)
            finally:
                self._connection = None
                self._device_info = None
    
    @property
    def is_connected(self) -> bool:
        """Check if currently connected to a YubiKey."""
        return self._connection is not None
    
    @property
    def device_info(self) -> Optional[YubiKeyInfo]:
        """Get info about the connected device, or None if not connected."""
        return self._device_info
    
    def __enter__(self) -> 'YubiKeyConnector':
        """Context manager entry - connects to YubiKey."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - closes connection."""
        self.close()
