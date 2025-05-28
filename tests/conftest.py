"""Shared test configuration and fixtures."""

import pytest
from datetime import datetime, timedelta, timezone, date
from unittest.mock import MagicMock
from pycsmeter._packets import (
    DashboardPacket,
    AdvancedPacket,
    WaterUsageHistoryPacket,
    WaterUsageHistoryItem,
    PacketParseError,
)


def pytest_configure(config):  # noqa: ARG001
    """Configure pytest."""
    pytest.register_assert_rewrite("tests.helpers")

@pytest.fixture
def valid_hello_data():
    """Create valid hello packet data."""
    data = bytearray([0x74, 0x74, 0x00] + [0] * 17)
    data[11] = 42  # seed
    data[7] = 0x80  # authenticated
    return bytes(data)

@pytest.fixture
def valid_dashboard_data():
    """Create valid dashboard packet data."""
    data = bytearray([0x75, 0x75, 0x00] + [0] * 17)
    data[3] = 14  # hour
    data[4] = 30  # minute
    return bytes(data)

@pytest.fixture
def valid_advanced_data():
    """Create valid advanced packet data."""
    data = bytearray([0x75, 0x75, 0x01] + [0] * 17)
    data[3] = 7  # regen_days
    data[4] = 3  # days_to_regen
    return bytes(data)

@pytest.fixture
def valid_history_chunks():
    """Create valid history packet chunks."""
    chunk1 = bytearray([0x75, 0x75, 2] + [i for i in range(17)])  # 19 bytes
    chunk2 = bytearray([i for i in range(20)])  # 20 bytes
    chunk3 = bytearray([i for i in range(20)])  # 20 bytes
    chunk4 = bytearray([i for i in range(5)])   # 5 bytes
    return [bytes(chunk1), bytes(chunk2), bytes(chunk3), bytes(chunk4)]

@pytest.fixture
def mock_water_usage_history_packet():
    """Create a mock water usage history packet."""
    mock = MagicMock(spec=WaterUsageHistoryPacket)
    mock.get_history_last_n_days.return_value = [
        WaterUsageHistoryItem(date=date.today() - timedelta(days=i), gallons_per_day=float(i))
        for i in range(62)
    ]
    mock.get_history_for_date.return_value = 42.0
    return mock
