"""Tests for packet parsing and handling."""

import json
from datetime import date, timedelta, datetime, timezone
import warnings
import pytest
from unittest.mock import patch

from pycsmeter._packets import (
    AdvancedPacket,
    DashboardPacket,
    HelloPacket,
    WaterUsageHistoryItem,
    WaterUsageHistoryPacket,
    InvalidPacket,
    LoginPacket,
    PacketParser,
    PasswordCrypto,
    ValveData,
)
from pycsmeter.exceptions import PacketParseError


@pytest.fixture(autouse=True)
def ignore_unraisable_warning():
    """Ignore PytestUnraisableExceptionWarning warnings."""
    warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)
    yield


@pytest.fixture
def valid_date():
    """Create a valid date object."""
    return date(2024, 1, 1)


@pytest.fixture
def valid_dashboard_data():
    """Create valid dashboard packet data."""
    data = bytearray([0] * 20)
    data[0] = 0x75  # Header bytes
    data[1] = 0x75
    data[2] = 0x00
    data[3] = 14  # hour
    data[4] = 30  # minute
    data[5] = 0  # hour_pm
    data[6] = 42  # battery_adc
    data[7:9] = (550).to_bytes(2, byteorder="big")  # current_flow (5.50)
    data[9:11] = (1000).to_bytes(2, byteorder="big")  # soft_remaining
    data[11:13] = (50).to_bytes(2, byteorder="big")  # treated_usage_today
    data[13:15] = (750).to_bytes(2, byteorder="big")  # peak_flow_today (7.50)
    data[15] = 15  # water_hardness
    data[16] = 2  # regen_hour
    data[17] = 0  # regen_hour_pm
    return bytes(data)


@pytest.fixture
def valid_advanced_data():
    """Create valid advanced packet data."""
    data = bytearray([0] * 20)
    data[0] = 0x75  # Add header bytes
    data[1] = 0x75
    data[2] = 1
    data[3] = 7  # regen_days
    data[4] = 3  # days_to_regen
    return bytes(data)


@pytest.fixture
def valid_hello_data():
    """Create valid hello packet data."""
    data = bytearray([0] * 20)
    data[0] = 0x74  # Header bytes
    data[1] = 0x74
    data[2] = 0x00
    data[5] = 1  # major_version
    data[6] = 0  # minor_version
    data[7] = 0x80  # authenticated
    data[11] = 42  # seed
    data[13:17] = bytes.fromhex("12345678")  # serial
    return bytes(data)


@pytest.fixture
def valid_history_items(valid_date):
    """Create valid history items."""
    items = []
    current_date = valid_date
    for i in range(62):
        items.append(HistoryItem(date=current_date, gallons_per_day=float(i * 10)))
        current_date -= timedelta(days=1)
    return items


@pytest.fixture
def valid_history_data():
    """Create valid history packet raw data."""
    return bytes([i for i in range(62)])


@pytest.fixture
def valid_dashboard_packet(valid_dashboard_data):
    """Create a valid dashboard packet."""
    return DashboardPacket.from_bytes(valid_dashboard_data)


@pytest.fixture
def valid_advanced_packet(valid_advanced_data):
    """Create a valid advanced packet."""
    return AdvancedPacket.from_bytes(valid_advanced_data)


@pytest.fixture
def valid_hello_packet(valid_hello_data):
    """Create a valid hello packet."""
    return HelloPacket.from_bytes(valid_hello_data)


@pytest.fixture
def valid_history_chunks():
    """Create valid history packet chunks."""
    chunk1 = bytearray([0x75, 0x75, 2] + [i for i in range(17)])  # 19 bytes
    chunk2 = bytearray([i for i in range(20)])  # 20 bytes
    chunk3 = bytearray([i for i in range(20)])  # 20 bytes
    chunk4 = bytearray([i for i in range(5)])   # 5 bytes
    return [bytes(chunk1), bytes(chunk2), bytes(chunk3), bytes(chunk4)]


@pytest.fixture
def valid_water_usage_history_packet(valid_history_chunks):
    """Create a valid history packet."""
    return WaterUsageHistoryPacket(valid_history_chunks)


@pytest.fixture
def valid_valve_data(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
    """Create a valid valve data object."""
    return ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)

class TestInvalidPacket:
    """Tests for InvalidPacket."""  

    def test_invalid_packet_creation(self):
        """Test creating an invalid packet."""
        packet = InvalidPacket()
        assert isinstance(packet, InvalidPacket)

    def test_invalid_packet_validation(self):
        """Test validating an invalid packet."""
        packet = InvalidPacket()
        packet.validate()  # Should not raise

    def test_invalid_packet_from_bytes(self):
        """Test creating invalid packet from bytes."""
        packet = InvalidPacket.from_bytes(b"test")
        assert isinstance(packet, InvalidPacket)
        packet = InvalidPacket.from_bytes(None)
        assert isinstance(packet, InvalidPacket)

    def test_invalid_packet_json(self):
        """Test JSON serialization of invalid packet."""
        packet = InvalidPacket()
        json_str = packet.to_json()
        assert json.loads(json_str) == {}

    def test_invalid_packet_repr(self):
        """Test string representation of invalid packet."""
        packet = InvalidPacket()
        assert repr(packet) == "<InvalidPacket>"

    def test_invalid_packet_equality(self):
        """Test equality comparison of invalid packets."""
        packet1 = InvalidPacket()
        packet2 = InvalidPacket()
        assert packet1 == packet2
        assert packet1 != object()


class TestDashboardPacket:
    """Tests for DashboardPacket."""

    def test_dashboard_packet_creation(self, valid_dashboard_data):
        """Test creating a dashboard packet."""
        packet = DashboardPacket(valid_dashboard_data)
        assert packet.hour == 14
        assert packet.minute == 30
        assert packet.hour_pm == 0
        assert packet.battery_adc == 42
        assert packet.battery_volt == pytest.approx(42 * 0.08797)
        assert packet.current_flow == 5.50
        assert packet.soft_remaining == 1000
        assert packet.treated_usage_today == 50
        assert packet.peak_flow_today == 7.50
        assert packet.water_hardness == 15
        assert packet.regen_hour == 2

    def test_dashboard_packet_validation(self, valid_dashboard_data):
        """Test dashboard packet validation."""
        packet = DashboardPacket(valid_dashboard_data)
        packet.validate()  # Should not raise

        # Test invalid values
        invalid_cases = [
            ("hour", 24),
            ("minute", 60),
            ("hour_pm", 2),
            ("battery_adc", 256),
            ("current_flow", 1000.0),
            ("soft_remaining", 65536),
            ("treated_usage_today", 65536),
            ("peak_flow_today", 1000.0),
            ("water_hardness", 256),
            ("regen_hour", 24),
        ]

        for field, invalid_value in invalid_cases:
            packet = DashboardPacket(valid_dashboard_data)
            setattr(packet, field, invalid_value)
            with pytest.raises(ValueError, match=f"{field} out of range"):
                packet.validate()

    def test_dashboard_packet_from_bytes(self, valid_dashboard_data):
        """Test creating dashboard packet from bytes."""
        packet = DashboardPacket.from_bytes(valid_dashboard_data)
        assert isinstance(packet, DashboardPacket)

        with pytest.raises(ValueError, match="Dashboard packet too short"):
            DashboardPacket.from_bytes(b"short")

    def test_dashboard_packet_json(self, valid_dashboard_data):
        """Test JSON serialization of dashboard packet."""
        packet = DashboardPacket(valid_dashboard_data)
        json_str = packet.to_json()
        data = json.loads(json_str)
        assert data["hour"] == 14
        assert data["minute"] == 30
        assert data["current_flow"] == 5.50

    def test_dashboard_packet_repr(self, valid_dashboard_data):
        """Test string representation of dashboard packet."""
        packet = DashboardPacket(valid_dashboard_data)
        assert repr(packet).startswith("<DashboardPacket")

    def test_dashboard_packet_equality(self, valid_dashboard_data):
        """Test equality comparison of dashboard packets."""
        packet1 = DashboardPacket(valid_dashboard_data)
        packet2 = DashboardPacket(valid_dashboard_data)
        assert packet1 == packet2
        assert packet1 != object()

    def test_dashboard_packet_regen_hour_pm_validation(self, valid_dashboard_data):
        """Test validation of regen_hour_pm field."""
        packet = DashboardPacket(valid_dashboard_data)
        packet.regen_hour_pm = 2  # Invalid value
        with pytest.raises(ValueError, match="regen_hour_pm out of range"):
            packet.validate()


class TestAdvancedPacket:
    """Tests for AdvancedPacket."""

    def test_advanced_packet_creation(self, valid_advanced_data):
        """Test creating an advanced packet."""
        packet = AdvancedPacket(valid_advanced_data)
        assert packet.regen_days == 7
        assert packet.days_to_regen == 3

    def test_advanced_packet_validation(self, valid_advanced_data):
        """Test advanced packet validation."""
        packet = AdvancedPacket(valid_advanced_data)
        packet.validate()  # Should not raise

        # Test invalid values
        invalid_cases = [
            ("regen_days", 256),
            ("days_to_regen", 256),
        ]

        for field, invalid_value in invalid_cases:
            packet = AdvancedPacket(valid_advanced_data)
            setattr(packet, field, invalid_value)
            with pytest.raises(ValueError, match=f"{field} out of range"):
                packet.validate()

    def test_advanced_packet_from_bytes(self, valid_advanced_data):
        """Test creating advanced packet from bytes."""
        packet = AdvancedPacket.from_bytes(valid_advanced_data)
        assert isinstance(packet, AdvancedPacket)
        assert packet.regen_days == 7
        assert packet.days_to_regen == 3

        with pytest.raises(ValueError, match="Advanced packet too short"):
            AdvancedPacket.from_bytes(b"sho")

    def test_advanced_packet_json(self, valid_advanced_data):
        """Test JSON serialization of advanced packet."""
        packet = AdvancedPacket(valid_advanced_data)
        json_str = packet.to_json()
        data = json.loads(json_str)
        assert data["regen_days"] == 7
        assert data["days_to_regen"] == 3

    def test_advanced_packet_repr(self, valid_advanced_data):
        """Test string representation of advanced packet."""
        packet = AdvancedPacket(valid_advanced_data)
        assert repr(packet).startswith("<AdvancedPacket")

    def test_advanced_packet_equality(self, valid_advanced_data):
        """Test equality comparison of advanced packets."""
        packet1 = AdvancedPacket(valid_advanced_data)
        packet2 = AdvancedPacket(valid_advanced_data)
        assert packet1 == packet2
        assert packet1 != object()

    def test_advanced_packet_too_short(self):
        """Test creating an advanced packet with too short data."""
        # Test with empty data
        with pytest.raises(ValueError, match="Advanced packet too short"):
            AdvancedPacket(b"")

        # Test with data shorter than 5 bytes
        with pytest.raises(ValueError, match="Advanced packet too short"):
            AdvancedPacket(bytes([0x75, 0x75, 0x01, 0x07]))  # Only 4 bytes

        # Test that 5 bytes is accepted
        data = bytearray([0x75, 0x75, 0x01, 0x07, 0x03])
        packet = AdvancedPacket(data)
        assert packet.regen_days == 7
        assert packet.days_to_regen == 3

class TestWaterUsageHistoryPacket:
    """Tests for WaterUsageHistoryPacket."""

    def test_history_packet_creation(self, valid_history_chunks):
        """Test creating a history packet from chunks."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)
        assert len(packet.history_data) == 62

    def test_history_packet_creation_invalid_chunks(self):
        """Test creating a history packet from invalid chunks."""
        # Test invalid first chunk
        invalid_chunk1 = bytearray([0x00, 0x00, 0] + [i for i in range(17)])
        chunk2 = bytearray([i for i in range(20)])
        chunk3 = bytearray([i for i in range(20)])
        chunk4 = bytearray([i for i in range(5)])

        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket([bytes(invalid_chunk1), bytes(chunk2), bytes(chunk3), bytes(chunk4)])

        # Test short second chunk
        chunk1 = bytearray([0x75, 0x75, 2] + [i for i in range(17)])
        short_chunk2 = bytearray([i for i in range(10)])
        with pytest.raises(PacketParseError, match="Second history chunk too short"):
            WaterUsageHistoryPacket([bytes(chunk1), bytes(short_chunk2), bytes(chunk3), bytes(chunk4)])

        # Test short third chunk
        short_chunk3 = bytearray([i for i in range(10)])
        with pytest.raises(PacketParseError, match="Third history chunk too short"):
            WaterUsageHistoryPacket([bytes(chunk1), bytes(chunk2), bytes(short_chunk3), bytes(chunk4)])

        # Test short fourth chunk
        short_chunk4 = bytearray([i for i in range(2)])
        with pytest.raises(PacketParseError, match="Fourth history chunk too short"):
            WaterUsageHistoryPacket([bytes(chunk1), bytes(chunk2), bytes(chunk3), bytes(short_chunk4)])

        # Test no chunks
        with pytest.raises(PacketParseError, match="No water usage history chunks provided"):
            WaterUsageHistoryPacket([])

    def test_history_packet_first_chunk_validation(self):
        """Test validation of the first water usage history chunk header bytes."""
        # Test with wrong header bytes (not 0x75 0x75)
        invalid_header = bytearray([0x74, 0x74, 2] + [0] * 17)  # Wrong header bytes
        chunk2 = bytearray([0] * 20)
        chunk3 = bytearray([0] * 20)
        chunk4 = bytearray([0] * 5)
        
        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket([bytes(invalid_header), bytes(chunk2), bytes(chunk3), bytes(chunk4)])
            
        # Test with wrong type byte (not 2)
        invalid_type = bytearray([0x75, 0x75, 1] + [0] * 17)  # Wrong type byte
        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket([bytes(invalid_type), bytes(chunk2), bytes(chunk3), bytes(chunk4)])
            
        # Test with too short first chunk
        short_chunk = bytearray([0x75, 0x75, 2] + [0] * 15)  # Only 18 bytes instead of 20
        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket([bytes(short_chunk), bytes(chunk2), bytes(chunk3), bytes(chunk4)])

    def test_history_packet_validation_data_length(self):
        """Test validation of history data length."""
        # Create valid chunks but manipulate the history_data after creation
        chunk1 = bytearray([0x75, 0x75, 2] + [0] * 17)
        chunk2 = bytearray([0] * 20)
        chunk3 = bytearray([0] * 20)
        chunk4 = bytearray([0] * 5)
        
        packet = WaterUsageHistoryPacket([bytes(chunk1), bytes(chunk2), bytes(chunk3), bytes(chunk4)])
        
        # Test with too short history data
        packet.history_data = packet.history_data[:-1]  # Remove last byte
        with pytest.raises(ValueError, match="History data must be 62 bytes"):
            packet.validate()
            
        # Test with too long history data
        packet.history_data = packet.history_data + bytes([0, 0])  # Add two extra bytes
        with pytest.raises(ValueError, match="History data must be 62 bytes"):
            packet.validate()
    
    def test_history_packet_validation(self, valid_history_chunks):
        """Test history packet validation."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)
        packet.validate()  # Should not raise

        # Test invalid data length
        packet.history_data = packet.history_data[:-1]  # Remove last byte
        with pytest.raises(ValueError, match="History data must be 62 bytes"):
            packet.validate()

    def test_get_history_for_date(self, valid_history_chunks):
        """Test getting history for specific date."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)

        # Test getting yesterday's data
        yesterday = packet.yesterday
        gallons = packet.get_history_for_date(yesterday)
        assert gallons is not None
        assert isinstance(gallons, float)

        # Test getting data from 61 days ago
        old_date = yesterday - timedelta(days=61)
        gallons = packet.get_history_for_date(old_date)
        assert gallons is not None
        assert isinstance(gallons, float)

        # Test getting data from too old date
        too_old = yesterday - timedelta(days=100)
        assert packet.get_history_for_date(too_old) is None

        # Test getting future date
        future = yesterday + timedelta(days=1)
        assert packet.get_history_for_date(future) is None

    def test_get_history_last_n_days(self, valid_history_chunks):
        """Test getting last N days of history."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)

        # Test getting 10 days
        history = packet.get_history_last_n_days(10)
        assert len(history) == 10
        assert all(isinstance(item, WaterUsageHistoryItem) for item in history)
        assert all(isinstance(item.date, date) and isinstance(item.gallons_per_day, float) 
                  for item in history)

        # Test getting more than 62 days (should be capped)
        history = packet.get_history_last_n_days(100)
        assert len(history) == 62

        # Test getting 0 days
        history = packet.get_history_last_n_days(0)
        assert len(history) == 0

    def test_history_packet_json(self, valid_history_chunks):
        """Test JSON serialization of history packet."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)
        json_str = packet.to_json()
        data = json.loads(json_str)
        assert len(data) == 62
        assert all("date" in item and "gallons_per_day" in item for item in data)

        # Test with indent
        json_str_indented = packet.to_json(indent=2)
        assert isinstance(json_str_indented, str)
        assert json_str_indented.count("\n") > 0  # Should be formatted with newlines

    def test_history_packet_repr(self, valid_history_chunks):
        """Test string representation of history packet."""
        packet = WaterUsageHistoryPacket(valid_history_chunks)
        assert repr(packet) == "<WaterUsageHistoryPacket 62 bytes>"

    def test_merge_history_chunks_header_validation(self):
        """Test validation of history chunk header bytes (line 213)."""
        # Test with wrong header bytes (not 0x75 0x75)
        invalid_header = bytes([0x74, 0x74, 2] + [0] * 17)  # Wrong header bytes
        chunk2 = bytes([0] * 20)
        chunk3 = bytes([0] * 20)
        chunk4 = bytes([0] * 5)
        
        with pytest.raises(PacketParseError, match="No history chunks provided"):
            WaterUsageHistoryPacket._merge_history_chunks([])

        with pytest.raises(PacketParseError, match="Invalid number of history chunks"):
            WaterUsageHistoryPacket._merge_history_chunks([invalid_header])

        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket._merge_history_chunks([invalid_header, chunk2, chunk3, chunk4])
            
        # Test with wrong type byte (not 2)
        invalid_type = bytes([0x75, 0x75, 1] + [0] * 17)  # Wrong type byte
        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket._merge_history_chunks([invalid_type, chunk2, chunk3, chunk4])
            
        # Test with too short first chunk
        short_chunk = bytes([0x75, 0x75, 2] + [0] * 15)  # Only 18 bytes instead of 19
        with pytest.raises(PacketParseError, match="Invalid first water usage history chunk"):
            WaterUsageHistoryPacket._merge_history_chunks([short_chunk, chunk2, chunk3, chunk4])

    def test_history_data_length_validation(self):
        """Test validation of history data length (line 240)."""
        # Create a valid history packet first
        chunk1 = bytes([0x75, 0x75, 2] + [0] * 17)  # 20 bytes with header
        chunk2 = bytes([0] * 20)
        chunk3 = bytes([0] * 20)
        chunk4 = bytes([0] * 5)
        
        packet = WaterUsageHistoryPacket([chunk1, chunk2, chunk3, chunk4])
        
        # Test with too short history data
        packet.history_data = bytes([0] * 61)  # One byte too short
        with pytest.raises(ValueError, match="History data must be 62 bytes"):
            packet.validate()
            
        # Test with too long history data
        packet.history_data = bytes([0] * 63)  # One byte too long
        with pytest.raises(ValueError, match="History data must be 62 bytes"):
            packet.validate()
            
        # Test with exactly 62 bytes (should pass)
        packet.history_data = bytes([0] * 62)
        packet.validate()  # Should not raise

class TestHelloPacket:
    """Tests for HelloPacket."""

    def test_hello_packet_creation(self, valid_hello_data):
        """Test creating a hello packet."""
        packet = HelloPacket(valid_hello_data)
        assert packet.seed == 42
        assert packet.major_version == 1
        assert packet.minor_version == 0
        assert packet.version == 100
        assert packet.serial == "12345678"
        assert packet.authenticated is True

    def test_hello_packet_validation(self, valid_hello_data):
        """Test hello packet validation."""
        packet = HelloPacket(valid_hello_data)
        packet.validate()  # Should not raise

        # Test invalid values
        invalid_cases = [
            ("seed", 256),
            ("major_version", 256),
            ("minor_version", 256),
            ("serial", "123"),
            ("authenticated", "True"),
        ]

        for field, invalid_value in invalid_cases:
            packet = HelloPacket(valid_hello_data)
            setattr(packet, field, invalid_value)
            with pytest.raises((ValueError, TypeError)):
                packet.validate()

    def test_hello_packet_from_bytes(self, valid_hello_data):
        """Test creating hello packet from bytes."""
        packet = HelloPacket.from_bytes(valid_hello_data)
        assert isinstance(packet, HelloPacket)

        with pytest.raises(ValueError, match="Invalid hello packet length"):
            HelloPacket.from_bytes(b"short")

    def test_hello_packet_json(self, valid_hello_data):
        """Test JSON serialization of hello packet."""
        packet = HelloPacket(valid_hello_data)
        json_str = packet.to_json()
        data = json.loads(json_str)
        assert data["seed"] == 42
        assert data["major_version"] == 1
        assert data["minor_version"] == 0
        assert data["version"] == 100
        assert data["serial"] == "12345678"
        assert data["authenticated"] is True

    def test_hello_packet_repr(self, valid_hello_data):
        """Test string representation of hello packet."""
        packet = HelloPacket(valid_hello_data)
        assert repr(packet).startswith("<HelloPacket")

    def test_hello_packet_equality(self, valid_hello_data):
        """Test equality comparison of hello packets."""
        packet1 = HelloPacket(valid_hello_data)
        packet2 = HelloPacket(valid_hello_data)
        assert packet1 == packet2
        assert packet1 != object()


class TestPasswordCrypto:
    """Tests for PasswordCrypto."""

    def test_password_crypto_init(self):
        """Test initializing password crypto."""
        crypto = PasswordCrypto()
        crypto.init(0x42, 0x99)
        assert crypto.idx == 0x42
        assert crypto.factor == 0x99

    def test_password_crypto_rotate(self):
        """Test password crypto rotation."""
        crypto = PasswordCrypto()
        crypto.init(0x42, 0x99)
        result = crypto.rotate(0x55)
        assert isinstance(result, int)
        assert 0 <= result <= 255


class TestLoginPacket:
    """Tests for LoginPacket."""

    def test_login_packet_creation(self):
        """Test creating a login packet."""
        packet = LoginPacket(42, "1234")
        assert packet.seed == 42
        assert packet.pin == 1234

    def test_login_packet_invalid_password(self):
        """Test login packet with invalid password."""
        with pytest.raises(ValueError, match="Password must be convertible to int"):
            LoginPacket(42, "invalid")

    def test_get_pin_to_array(self):
        """Test converting PIN to array."""
        packet = LoginPacket(42, "1234")
        array = packet.get_pin_to_array(1234)
        assert array == [4, 3, 2, 1]

        # Test PIN range limits
        assert packet.get_pin_to_array(-1) == [0, 0, 0, 0]
        assert packet.get_pin_to_array(10000) == [9, 9, 9, 9]

    def test_generate_login_packet(self):
        """Test generating login packet bytes."""
        packet = LoginPacket(42, "1234")
        data = packet.generate()
        assert isinstance(data, bytes)
        assert len(data) == 20
        assert data[0] == 0x74  # Header byte

    def test_login_packet_generate_different_password(self):
        """Test generating login packet with different password."""
        packet1 = LoginPacket(42, "1234")
        packet2 = LoginPacket(42, "5678")
        data1 = packet1.generate()
        data2 = packet2.generate()
        assert data1 != data2  # Different passwords should produce different packets
        assert len(data1) == len(data2) == 20  # But same length
        assert data1[0] == data2[0] == 0x74  # Same header byte


class TestPacketParser:
    """Tests for PacketParser."""

    @pytest.fixture
    def parser(self):
        """Create a packet parser instance."""
        return PacketParser()

    @pytest.mark.asyncio
    async def test_parse_hello_packet(self, parser, valid_hello_data):
        """Test parsing hello packet."""
        result = await parser.parse([valid_hello_data])
        assert isinstance(result, HelloPacket)
        assert result.seed == 42
        assert result.authenticated is True

        # Test with wrong number of chunks
        with pytest.raises(PacketParseError, match="Expected only one data chunk"):
            await parser.parse([valid_hello_data, valid_hello_data])

    @pytest.mark.asyncio
    async def test_parse_dashboard_packet(self, parser, valid_dashboard_data):
        """Test parsing dashboard packet."""
        result = await parser.parse([valid_dashboard_data])
        assert isinstance(result, DashboardPacket)
        assert result.hour == 14
        assert result.minute == 30

        # Test with wrong number of chunks
        with pytest.raises(PacketParseError, match="Expected only one data chunk"):
            await parser.parse([valid_dashboard_data, valid_dashboard_data])

    @pytest.mark.asyncio
    async def test_parse_advanced_packet(self, parser, valid_advanced_data):
        """Test parsing advanced packet."""
        result = await parser.parse([valid_advanced_data])
        assert isinstance(result, AdvancedPacket)
        assert result.regen_days == 7
        assert result.days_to_regen == 3

        # Test with wrong number of chunks
        with pytest.raises(PacketParseError, match="Expected only one data chunk"):
            await parser.parse([valid_advanced_data, valid_advanced_data])

    @pytest.mark.asyncio
    async def test_parse_history_packet(self, parser, valid_history_chunks):
        """Test parsing history packet chunks."""
        result = await parser.parse(valid_history_chunks)
        assert isinstance(result, WaterUsageHistoryPacket)
        assert len(result.history_data) == 62

        # Test with wrong number of chunks
        with pytest.raises(PacketParseError, match="Expected four data chunks"):
            await parser.parse(valid_history_chunks[:3])

    @pytest.mark.asyncio
    async def test_parse_unknown_packet(self, parser):
        """Test parsing unknown packet type."""
        with pytest.raises(PacketParseError, match="Unknown packet type"):
            await parser.parse([bytes([0x00] * 20)])

    @pytest.mark.asyncio
    async def test_parse_empty_data(self, parser):
        """Test parsing with no data."""
        with pytest.raises(PacketParseError, match="No data provided"):
            await parser.parse([])


class TestValveData:
    """Tests for ValveData class."""

    def test_valve_data_creation(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test creating valve data."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        assert isinstance(valve_data.dashboard, DashboardPacket)
        assert isinstance(valve_data.advanced, AdvancedPacket)
        assert isinstance(valve_data.water_usage_history, WaterUsageHistoryPacket)

    def test_get_history(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test getting history items."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        history = valve_data.get_history()
        assert len(history) == 62
        assert all(isinstance(item, WaterUsageHistoryItem) for item in history)

    def test_get_history_for_date(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test getting history for specific date."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        gallons = valve_data.get_history_for_date(valid_water_usage_history_packet.yesterday)
        assert gallons is not None
        assert isinstance(gallons, float)

        # Test non-existent date
        assert valve_data.get_history_for_date(date(2000, 1, 1)) is None

    def test_get_history_last_n_days(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test getting last N days of history."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        history = valve_data.get_history_last_n_days(10)
        assert len(history) == 10
        assert all(isinstance(item, WaterUsageHistoryItem) for item in history)

    def test_validate(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test validating valve data."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        valve_data.validate()  # Should not raise

    def test_to_json(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test JSON serialization of valve data."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        json_str = valve_data.to_json()
        data = json.loads(json_str)
        assert "dashboard" in data
        assert "advanced" in data
        assert "history" in data

        # Test with indent
        json_str_indented = valve_data.to_json(indent=2)
        assert isinstance(json_str_indented, str)
        assert json_str_indented.count("\n") > 0  # Should be formatted with newlines

    def test_repr(self, valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet):
        """Test string representation of valve data."""
        valve_data = ValveData(valid_dashboard_packet, valid_advanced_packet, valid_water_usage_history_packet)
        repr_str = repr(valve_data)
        assert repr_str.startswith("<ValveData")
        assert "dashboard=" in repr_str
        assert "advanced=" in repr_str
        assert "history_items=62" in repr_str
