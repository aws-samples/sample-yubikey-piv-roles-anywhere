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
Property-based tests for YubiKey serial number selection.

Feature: yubikey-iam-roles-anywhere, Property 1: Serial Number Selection
Validates: Requirements 1.2
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
from unittest.mock import patch, MagicMock

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from yubira.yubikey_connector import (
    YubiKeyConnector,
    YubiKeyInfo,
    YubiKeyNotFoundError,
)


# Strategy for generating valid YubiKey serial numbers (positive integers)
serial_strategy = st.integers(min_value=1, max_value=99999999)

# Strategy for generating firmware versions
version_strategy = st.tuples(
    st.integers(min_value=1, max_value=5),
    st.integers(min_value=0, max_value=9),
    st.integers(min_value=0, max_value=9),
)


@dataclass
class MockDeviceInfo:
    """Mock device info matching ykman's DeviceInfo structure."""
    serial: int
    version: Tuple[int, int, int]


class MockDevice:
    """Mock YubiKey device for testing."""
    
    def __init__(self, serial: int, version: Tuple[int, int, int]):
        self.serial = serial
        self.version = version
    
    def open_connection(self, connection_type):
        """Return a mock connection."""
        mock_conn = MagicMock()
        return mock_conn


def create_mock_device_list(
    serials_and_versions: List[Tuple[int, Tuple[int, int, int]]]
) -> List[Tuple[MockDevice, MockDeviceInfo]]:
    """Create a mock device list matching ykman's list_all_devices format."""
    return [
        (MockDevice(serial, version), MockDeviceInfo(serial=serial, version=version))
        for serial, version in serials_and_versions
    ]


class TestSerialNumberSelection:
    """
    Property 1: Serial Number Selection
    
    For any list of YubiKey device information containing multiple devices 
    with distinct serial numbers, when a specific serial number is requested, 
    the connector SHALL return only the device matching that serial number.
    
    Validates: Requirements 1.2
    """

    @given(
        serials=st.lists(
            serial_strategy,
            min_size=2,
            max_size=10,
            unique=True,
        ),
        versions=st.lists(
            version_strategy,
            min_size=2,
            max_size=10,
        ),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_serial_selection_returns_matching_device(
        self, serials: List[int], versions: List[Tuple[int, int, int]]
    ):
        """
        Property: For any list of devices with distinct serials, selecting by 
        serial number returns exactly the device with that serial.
        
        Feature: yubikey-iam-roles-anywhere, Property 1: Serial Number Selection
        Validates: Requirements 1.2
        """
        # Ensure we have matching lengths
        assume(len(serials) == len(versions))
        
        # Create device list
        devices_data = list(zip(serials, versions))
        mock_devices = create_mock_device_list(devices_data)
        
        # Pick a random serial from the list to request
        target_serial = serials[0]
        target_version = versions[0]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            connector = YubiKeyConnector(serial=target_serial)
            device_info = connector.connect()
            
            # Property: The returned device MUST have the requested serial
            assert device_info.serial == target_serial
            assert device_info.version == target_version
            
            connector.close()

    @given(
        serials=st.lists(
            serial_strategy,
            min_size=1,
            max_size=10,
            unique=True,
        ),
        versions=st.lists(
            version_strategy,
            min_size=1,
            max_size=10,
        ),
        requested_serial=serial_strategy,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_serial_not_found_raises_error(
        self,
        serials: List[int],
        versions: List[Tuple[int, int, int]],
        requested_serial: int,
    ):
        """
        Property: For any serial not in the device list, selection raises 
        YubiKeyNotFoundError.
        
        Feature: yubikey-iam-roles-anywhere, Property 1: Serial Number Selection
        Validates: Requirements 1.2
        """
        # Ensure requested serial is NOT in the list
        assume(requested_serial not in serials)
        assume(len(serials) == len(versions))
        
        devices_data = list(zip(serials, versions))
        mock_devices = create_mock_device_list(devices_data)
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            connector = YubiKeyConnector(serial=requested_serial)
            
            with pytest.raises(YubiKeyNotFoundError) as exc_info:
                connector.connect()
            
            # Property: Error message MUST contain the requested serial
            assert str(requested_serial) in str(exc_info.value)

    @given(
        serials=st.lists(
            serial_strategy,
            min_size=2,
            max_size=10,
            unique=True,
        ),
        versions=st.lists(
            version_strategy,
            min_size=2,
            max_size=10,
        ),
        selection_index=st.integers(min_value=0, max_value=9),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_serial_selection_is_deterministic(
        self,
        serials: List[int],
        versions: List[Tuple[int, int, int]],
        selection_index: int,
    ):
        """
        Property: Serial selection is deterministic - same serial always 
        returns same device info.
        
        Feature: yubikey-iam-roles-anywhere, Property 1: Serial Number Selection
        Validates: Requirements 1.2
        """
        assume(len(serials) == len(versions))
        assume(selection_index < len(serials))
        
        devices_data = list(zip(serials, versions))
        mock_devices = create_mock_device_list(devices_data)
        
        target_serial = serials[selection_index]
        
        with patch('yubira.yubikey_connector.list_all_devices', return_value=mock_devices):
            # Connect twice with same serial
            connector1 = YubiKeyConnector(serial=target_serial)
            info1 = connector1.connect()
            connector1.close()
            
            connector2 = YubiKeyConnector(serial=target_serial)
            info2 = connector2.connect()
            connector2.close()
            
            # Property: Both connections return identical device info
            assert info1.serial == info2.serial
            assert info1.version == info2.version
