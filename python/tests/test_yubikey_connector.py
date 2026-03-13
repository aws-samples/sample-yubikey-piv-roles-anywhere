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
Unit tests for YubiKey Connector.

Tests device enumeration and connection error handling.
Requirements: 1.1, 1.5
"""

from unittest.mock import patch, MagicMock
from typing import Tuple

import pytest

from yubira.yubikey_connector import (
    YubiKeyConnector,
    YubiKeyInfo,
    YubiKeyNotFoundError,
    YubiKeyConnectionError,
)


class MockDeviceInfo:
    """Mock device info matching ykman's DeviceInfo structure."""
    def __init__(self, serial: int, version: Tuple[int, int, int]):
        self.serial = serial
        self.version = version


class MockDevice:
    """Mock YubiKey device for testing."""
    
    def __init__(self, serial: int, version: Tuple[int, int, int], fail_connection: bool = False):
        self.serial = serial
        self.version = version
        self._fail_connection = fail_connection
    
    def open_connection(self, connection_type):
        """Return a mock connection or raise an error."""
        if self._fail_connection:
            raise Exception("Simulated connection failure")
        mock_conn = MagicMock()
        return mock_conn


class TestDeviceEnumeration:
    """Tests for device enumeration functionality. Requirements: 1.1"""

    def test_list_devices_returns_empty_when_no_devices(self):
        """Test that list_devices returns empty list when no YubiKeys connected."""
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[]):
            devices = YubiKeyConnector.list_devices()
            assert devices == []

    def test_list_devices_returns_single_device(self):
        """Test that list_devices returns info for a single connected YubiKey."""
        mock_device = MockDevice(12345678, (5, 4, 3))
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            devices = YubiKeyConnector.list_devices()
            
            assert len(devices) == 1
            assert devices[0].serial == 12345678
            assert devices[0].version == (5, 4, 3)

    def test_list_devices_returns_multiple_devices(self):
        """Test that list_devices returns info for multiple connected YubiKeys."""
        mock_devices = [
            (MockDevice(11111111, (5, 2, 4)), MockDeviceInfo(serial=11111111, version=(5, 2, 4))),
            (MockDevice(22222222, (5, 4, 3)), MockDeviceInfo(serial=22222222, version=(5, 4, 3))),
            (MockDevice(33333333, (5, 1, 0)), MockDeviceInfo(serial=33333333, version=(5, 1, 0))),
        ]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            devices = YubiKeyConnector.list_devices()
            
            assert len(devices) == 3
            serials = [d.serial for d in devices]
            assert 11111111 in serials
            assert 22222222 in serials
            assert 33333333 in serials

    def test_list_devices_skips_devices_without_serial(self):
        """Test that devices without serial numbers are skipped."""
        mock_devices = [
            (MockDevice(11111111, (5, 2, 4)), MockDeviceInfo(serial=11111111, version=(5, 2, 4))),
            (MockDevice(None, (5, 4, 3)), MockDeviceInfo(serial=None, version=(5, 4, 3))),
        ]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            devices = YubiKeyConnector.list_devices()
            
            assert len(devices) == 1
            assert devices[0].serial == 11111111


class TestConnectionErrorHandling:
    """Tests for connection error handling. Requirements: 1.5"""

    def test_connect_raises_not_found_when_no_devices(self):
        """Test that connect raises YubiKeyNotFoundError when no devices detected."""
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[]):
            connector = YubiKeyConnector()
            
            with pytest.raises(YubiKeyNotFoundError) as exc_info:
                connector.connect()
            
            assert "No YubiKey detected" in str(exc_info.value)

    def test_connect_raises_not_found_for_missing_serial(self):
        """Test that connect raises YubiKeyNotFoundError when specified serial not found."""
        mock_device = MockDevice(12345678, (5, 4, 3))
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            connector = YubiKeyConnector(serial=99999999)
            
            with pytest.raises(YubiKeyNotFoundError) as exc_info:
                connector.connect()
            
            assert "99999999" in str(exc_info.value)

    def test_connect_raises_connection_error_on_failure(self):
        """Test that connect raises YubiKeyConnectionError when connection fails."""
        mock_device = MockDevice(12345678, (5, 4, 3), fail_connection=True)
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            connector = YubiKeyConnector()
            
            with pytest.raises(YubiKeyConnectionError) as exc_info:
                connector.connect()
            
            assert "Failed to connect" in str(exc_info.value)

    def test_get_piv_session_raises_when_not_connected(self):
        """Test that get_piv_session raises error when not connected."""
        connector = YubiKeyConnector()
        
        with pytest.raises(YubiKeyConnectionError) as exc_info:
            connector.get_piv_session()
        
        assert "Not connected" in str(exc_info.value)


class TestContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_connects_and_closes(self):
        """Test that context manager properly connects and closes."""
        mock_device = MockDevice(12345678, (5, 4, 3))
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            with YubiKeyConnector() as connector:
                assert connector.is_connected
                assert connector.device_info.serial == 12345678
            
            # After exiting context, should be disconnected
            assert not connector.is_connected
            assert connector.device_info is None

    def test_context_manager_closes_on_exception(self):
        """Test that context manager closes connection even when exception occurs."""
        mock_device = MockDevice(12345678, (5, 4, 3))
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            try:
                with YubiKeyConnector() as connector:
                    assert connector.is_connected
                    raise ValueError("Test exception")
            except ValueError:
                pass
            
            # Connection should still be closed
            assert not connector.is_connected


class TestConnectSuccess:
    """Tests for successful connection scenarios."""

    def test_connect_to_first_device_when_no_serial_specified(self):
        """Test that connect uses first device when no serial specified."""
        mock_devices = [
            (MockDevice(11111111, (5, 2, 4)), MockDeviceInfo(serial=11111111, version=(5, 2, 4))),
            (MockDevice(22222222, (5, 4, 3)), MockDeviceInfo(serial=22222222, version=(5, 4, 3))),
        ]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            connector = YubiKeyConnector()
            device_info = connector.connect()
            
            assert device_info.serial == 11111111
            assert connector.is_connected
            connector.close()

    def test_connect_to_specific_serial(self):
        """Test that connect finds device with specified serial."""
        mock_devices = [
            (MockDevice(11111111, (5, 2, 4)), MockDeviceInfo(serial=11111111, version=(5, 2, 4))),
            (MockDevice(22222222, (5, 4, 3)), MockDeviceInfo(serial=22222222, version=(5, 4, 3))),
        ]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            connector = YubiKeyConnector(serial=22222222)
            device_info = connector.connect()
            
            assert device_info.serial == 22222222
            assert device_info.version == (5, 4, 3)
            connector.close()

    def test_close_is_idempotent(self):
        """Test that calling close multiple times is safe."""
        mock_device = MockDevice(12345678, (5, 4, 3))
        mock_info = MockDeviceInfo(serial=12345678, version=(5, 4, 3))
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=[(mock_device, mock_info)]):
            connector = YubiKeyConnector()
            connector.connect()
            
            # Close multiple times - should not raise
            connector.close()
            connector.close()
            connector.close()
            
            assert not connector.is_connected
