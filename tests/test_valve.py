"""Tests for the valve module."""

import asyncio
from datetime import date, timedelta
from unittest.mock import AsyncMock, MagicMock, call, patch
import warnings

import pytest
import pytest_asyncio
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from pycsmeter._packets import (
    AdvancedPacket,
    DashboardPacket,
    HelloPacket,
    WaterUsageHistoryPacket,
    InvalidPacket,
    LoginPacket,
    WaterUsageHistoryPacket,
    WaterUsageHistoryItem,
)
from pycsmeter._packets import (
    WaterUsageHistoryItem as _WaterUsageHistoryItem,
)
from pycsmeter.exceptions import (
    AuthenticationError,
    DataRetrievalError,
    PacketParseError,
    PacketValidationError,
    ValveConnectionError,
)
from pycsmeter.valve import (
    NORDIC_UART_READ,
    NORDIC_UART_WRITE,
    AdvancedData,
    DashboardData,
    Valve,
    ValveData,
)


@pytest.fixture(autouse=True)
def event_loop():
    """Create and set an event loop for each test."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def mock_uart_service():
    """Create a mock UART service with read and write characteristics."""
    service = MagicMock()

    read_char = MagicMock(spec=BleakGATTCharacteristic)
    read_char.uuid = str(NORDIC_UART_READ)

    write_char = MagicMock(spec=BleakGATTCharacteristic)
    write_char.uuid = str(NORDIC_UART_WRITE)

    service.characteristics = [read_char, write_char]
    return service


@pytest_asyncio.fixture
async def mock_bleak_client(mock_uart_service):
    """Create a mock BleakClient with UART service."""
    with patch("pycsmeter.valve.BleakClient") as mock:
        client = AsyncMock(spec=BleakClient)
        client.services = [mock_uart_service]
        client.write_gatt_char = AsyncMock()
        client.start_notify = AsyncMock()
        client.connect = AsyncMock()
        client.disconnect = AsyncMock()
        client.is_connected = False

        # Add proper cleanup behavior
        async def mock_connect():
            client.is_connected = True
            return True

        async def mock_disconnect():
            client.is_connected = False
            # Ensure any notification handlers are cleaned up
            client.start_notify.reset_mock()

        client.connect.side_effect = mock_connect
        client.disconnect.side_effect = mock_disconnect

        mock.return_value = client
        yield client

        # Ensure cleanup
        if client.is_connected:
            await client.disconnect()


@pytest_asyncio.fixture
async def mock_valve(mock_bleak_client):
    """Create a mock Valve instance with proper cleanup."""
    valve = Valve("00:11:22:33:44:55")
    yield valve
    if valve.connected:
        await valve.disconnect()


@pytest.fixture
def mock_hello_packet():
    """Create a mock HelloPacket."""
    packet = MagicMock(spec=HelloPacket)
    packet.seed = 42
    packet.authenticated = True
    packet.major_version = 1
    packet.minor_version = 0
    packet.version = 100
    packet.serial = "12345678"
    return packet


@pytest.fixture
def mock_dashboard_packet():
    """Create a DashboardPacket instance."""
    data = bytearray([0] * 20)
    data[0] = 0x75  # Header bytes
    data[1] = 0x75
    data[2] = 0x00  # Type
    data[3] = 14    # hour
    data[4] = 30    # minute
    data[5] = 0     # hour_pm
    data[6] = 38    # battery_adc (38 * 0.08797 ≈ 3.3V)
    data[7:9] = (550).to_bytes(2, byteorder="big")    # current_flow (5.50)
    data[9:11] = (1000).to_bytes(2, byteorder="big")  # soft_remaining
    data[11:13] = (50).to_bytes(2, byteorder="big")   # treated_usage_today
    data[13:15] = (750).to_bytes(2, byteorder="big")  # peak_flow_today (7.50)
    data[15] = 15   # water_hardness
    data[16] = 2    # regen_hour
    data[17] = 0    # regen_hour_pm
    return DashboardPacket(bytes(data))


@pytest.fixture
def mock_advanced_packet():
    """Create an AdvancedPacket instance."""
    data = bytearray([0] * 20)
    data[0] = 0x75  # Header bytes
    data[1] = 0x75
    data[2] = 0x01  # Type
    data[3] = 7     # regen_days
    data[4] = 3     # days_to_regen
    return AdvancedPacket(bytes(data))


@pytest.fixture
def mock_water_usage_history_packet():
    """Create a WaterUsageHistoryPacket instance."""
    # Create history chunks with data that will result in the expected values
    chunk1 = bytearray([0x75, 0x75, 2] + [0] * 17)  # First chunk with header
    chunk2 = bytearray([0] * 20)  # Second chunk
    chunk3 = bytearray([0] * 20)  # Third chunk
    chunk4 = bytearray([0] * 5)   # Fourth chunk
    
    # Create history packet from chunks
    packet = WaterUsageHistoryPacket([bytes(chunk1), bytes(chunk2), bytes(chunk3), bytes(chunk4)])
    
    # Create history data that will result in the expected values
    # Each byte pair represents a gallons value
    history_data = bytearray([0] * 62)
    for i in range(62):
        if i == 0:  # First entry (yesterday) = 100.0 gallons
            history_data[i] = 10  # 100.0 gallons
        elif i == 1:  # Second entry = 150.0 gallons
            history_data[i] = 15
        else:
            history_data[i] = 0
    
    packet.history_data = bytes(history_data)
    packet.yesterday = date(2024, 1, 13)
    return packet


@pytest_asyncio.fixture
async def mock_packet_parser():
    """Create a mock PacketParser."""
    parser = AsyncMock()
    parser.parse = AsyncMock()
    return parser


@pytest.fixture(autouse=True)
def ignore_unraisable_warning():
    """Ignore PytestUnraisableExceptionWarning warnings."""
    warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)
    yield


class TestValveData:
    """Tests for the ValveData class."""

    def test_from_internal(self, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet):
        """Test converting internal packet types to ValveData."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet)

        assert isinstance(valve_data.dashboard, DashboardData)
        assert valve_data.dashboard.hour == 14
        assert valve_data.dashboard.minute == 30
        assert valve_data.dashboard.battery_voltage == 3.3428600000000004
        assert valve_data.dashboard.current_flow == 5.5
        assert valve_data.dashboard.soft_water_remaining == 1000
        assert valve_data.dashboard.treated_usage_today == 50
        assert valve_data.dashboard.peak_flow_today == 7.5
        assert valve_data.dashboard.water_hardness == 15
        assert valve_data.dashboard.regeneration_hour == 2

        assert isinstance(valve_data.advanced, AdvancedData)
        assert valve_data.advanced.regeneration_days == 7
        assert valve_data.advanced.days_to_regeneration == 3

        assert len(valve_data.water_usage_history) == 62
        assert valve_data.water_usage_history[0].gallons_per_day == 100.0
        assert valve_data.water_usage_history[1].gallons_per_day == 150.0

    def test_get_history_for_date(self, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet):
        """Test retrieving history for a specific date."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet)
        yesterday = mock_water_usage_history_packet.yesterday

        gallons = valve_data.get_history_for_date(yesterday)
        assert gallons is not None
        assert isinstance(gallons, float)
        assert gallons == 100.0  # Value from mock_history_packet

        gallons = valve_data.get_history_for_date(date(2020, 1, 1))
        assert gallons is None

    def test_get_history_last_n_days(self, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet):
        """Test retrieving last N days of history."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet)

        history = valve_data.get_history_last_n_days(1)
        assert len(history) == 1
        assert history[0].gallons_per_day == 100.0

        history = valve_data.get_history_last_n_days(2)
        assert len(history) == 2
        assert history[0].gallons_per_day == 100.0
        assert history[1].gallons_per_day == 150.0


class TestValve:
    """Tests for the Valve class."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup_teardown(self):
        """Set up test environment and clean up after each test."""
        # Setup
        self.client = None
        self.valve = None
        yield
        # Teardown
        if self.valve and self.valve.connected:
            await self.valve.disconnect()
        if self.client and self.client.is_connected:
            await self.client.disconnect()

    async def setup_valve_with_client(self, mock_bleak_client):
        """Helper to set up a valve with a mock client."""
        self.client = mock_bleak_client
        self.valve = Valve("00:11:22:33:44:55")
        self.valve.client = mock_bleak_client
        return self.valve

    @pytest.fixture
    def valve(self, mock_bleak_client, mock_packet_parser):
        """Create a Valve instance with mocked dependencies."""
        with patch("pycsmeter.valve._PacketParser", return_value=mock_packet_parser):
            valve = Valve("00:11:22:33:44:55")
            return valve

    def test_init_queue(self, valve):
        """Test that packet queue is properly initialized (line 145)."""
        # Verify queue is an asyncio Queue instance
        assert isinstance(valve.packet_queue, asyncio.Queue)

        # Verify queue is empty
        assert valve.packet_queue.empty()

        # Verify queue has no size limit (maxsize=0)
        assert valve.packet_queue._maxsize == 0

    @pytest.mark.asyncio
    async def test_queue_notification_handling(self, valve):
        """Test queue behavior with notification handler (line 145)."""
        # Test notification handler puts data in queue
        test_data = bytearray(b"test_notification")
        valve._notification_handler(None, test_data)
        assert not valve.packet_queue.empty()

        # Verify we can get the data asynchronously
        queued_data = await valve.packet_queue.get()
        assert queued_data == test_data
        assert valve.packet_queue.empty()

        # Test multiple notifications
        test_packets = [
            bytearray(b"packet1"),
            bytearray(b"packet2"),
            bytearray(b"packet3"),
        ]

        # Send multiple notifications
        for packet in test_packets:
            valve._notification_handler(None, packet)

        # Verify all packets are queued in order
        assert valve.packet_queue.qsize() == len(test_packets)

        # Verify we can get all packets in order
        for expected_packet in test_packets:
            received = await valve.packet_queue.get()
            assert received == expected_packet

        assert valve.packet_queue.empty()

        # Test queue doesn't block on full
        for _ in range(100):  # Try to overflow the queue
            valve._notification_handler(None, bytearray(b"test"))

        # Should still be able to add more
        valve._notification_handler(None, bytearray(b"one_more"))
        assert not valve.packet_queue.full()  # Queue should never be full

    @pytest.mark.asyncio
    async def test_id(self, valve):
        """Test getting valve identifier (line 151)."""
        valve_id = await valve.id()
        assert valve_id == "00:11:22:33:44:55"

    @pytest.mark.asyncio
    async def test_send_login(self, valve, mock_bleak_client):
        """Test sending login packet (line 174)."""
        # Setup UART write characteristic
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Create a test login packet
        test_packet = bytes([0x76] * 20)

        # Send login packet
        await valve._Valve__send_login(test_packet)

        # Verify the packet was sent correctly
        mock_bleak_client.write_gatt_char.assert_called_once_with(
            write_char,
            test_packet,
            response=False,
        )

    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, valve, mock_bleak_client):
        """Test disconnecting when connected (line 187)."""
        valve.connected = True
        await valve.disconnect()
        assert valve.connected is False
        mock_bleak_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self, valve, mock_bleak_client):
        """Test disconnecting when not connected."""
        valve.connected = False
        await valve.disconnect()
        mock_bleak_client.disconnect.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_data_retry_logic(
        self, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet
    ):
        """Test get_data retry logic for getting data."""
        valve = await self.setup_valve_with_client(mock_bleak_client)
        valve.connected = True
        valve.authenticated = True

        # Setup UART characteristics
        read_char = mock_bleak_client.services[0].characteristics[0]
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart = {
            NORDIC_UART_READ: read_char,
            NORDIC_UART_WRITE: write_char
        }

        # Create valid packet data - using correct hex values
        # Each packet has 3 header bytes (0x75, 0x75, type) followed by 17 bytes payload
        dashboard_bytes = bytes.fromhex("757500") + bytes([0] * 17)  # Dashboard packet (20 bytes)
        advanced_bytes = bytes.fromhex("757501") + bytes([0] * 17)   # Advanced packet (20 bytes)
        history_chunk1 = bytes.fromhex("757502") + bytes([0] * 17)   # History chunk 1 (20 bytes)
        history_chunk2 = bytes([0] * 20)   # History chunk 2 (20 bytes)
        history_chunk3 = bytes([0] * 20)   # History chunk 3 (20 bytes)
        history_chunk4 = bytes([0] * 5)    # History chunk 4 (5 bytes)
        invalid_bytes = bytes([0] * 20)  # Invalid packet

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,  # First attempt - dashboard
            advanced_bytes,  # First attempt - advanced
            invalid_bytes,  # First attempt - history chunk 1 (fails)
            invalid_bytes,  # First attempt - history chunk 2 (fails)
            invalid_bytes,  # First attempt - history chunk 3 (fails)
            invalid_bytes,  # First attempt - history chunk 4 (fails)
            dashboard_bytes,  # Second attempt - dashboard
            advanced_bytes,  # Second attempt - advanced
            history_chunk1,  # Second attempt - history chunk 1
            history_chunk2,  # Second attempt - history chunk 2
            history_chunk3,  # Second attempt - history chunk 3
            history_chunk4,  # Second attempt - history chunk 4
        ]
        valve.packet_queue = mock_queue

        # First attempt fails due to invalid packet, second succeeds
        mock_packet_parser.parse.side_effect = [
            mock_dashboard_packet,  # First attempt - dashboard
            mock_advanced_packet,  # First attempt - advanced
            PacketParseError("Unknown packet type"),  # First attempt - history fails due to invalid packet
            mock_dashboard_packet,  # Second attempt - dashboard
            mock_advanced_packet,  # Second attempt - advanced
            mock_water_usage_history_packet,  # Second attempt - history succeeds
        ]

        with patch("asyncio.sleep") as mock_sleep:
            result = await valve.get_data()
            mock_sleep.assert_called_once_with(0.1)

        assert isinstance(result, ValveData)
        assert mock_bleak_client.write_gatt_char.call_count == 2  # Initial request + retry

        # Verify queue operations - 12 packets total
        assert mock_queue.get.await_count == 12

        # Verify write operations
        for call in mock_bleak_client.write_gatt_char.call_args_list:
            assert call == call(write_char, bytes([0x75] * 20), response=False)

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, valve):
        """Test connecting when already connected."""
        valve.connected = True
        with pytest.raises(ValveConnectionError, match="already connected"):
            await valve.connect("1234")

    @pytest.mark.asyncio
    async def test_connect_success(self, valve, mock_bleak_client, mock_hello_packet, mock_packet_parser):
        """Test successful connection and authentication."""
        try:
            # Setup mock queue
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = [
                bytes([0x74] * 20),  # Initial hello packet
                bytes([0x74] * 20),  # Auth response packet
            ]
            valve.packet_queue = mock_queue

            # Setup hello packet responses
            hello_response = HelloPacket(bytes([0x74] * 20))
            hello_response.seed = 42
            hello_response.authenticated = True
            mock_packet_parser.parse.side_effect = [hello_response, hello_response]

            # Mock login packet
            with patch("pycsmeter.valve._LoginPacket") as mock_login:
                mock_login_instance = MagicMock()
                mock_login_instance.generate.return_value = bytes([0x74] * 20)
                mock_login.return_value = mock_login_instance

                # Attempt connection
                result = await valve.connect("1234")

                # Verify success
                assert result is True
                assert valve.connected is True
                assert valve.authenticated is True

                # Verify BLE operations
                mock_bleak_client.connect.assert_called_once()
                mock_bleak_client.start_notify.assert_called_once()

                # Verify packet handling
                assert mock_queue.get.await_count == 2
                assert mock_packet_parser.parse.call_count == 2

                # Verify login packet creation and usage
                mock_login.assert_called_once_with(42, "1234")
                mock_login_instance.generate.assert_called_once()

        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_connect_missing_uart(self, valve):
        """Test connection failure when UART characteristics are missing."""
        # Create a client with no UART service
        with patch("pycsmeter.valve.BleakClient") as mock:
            client = AsyncMock(spec=BleakClient)
            client.services = []  # No services
            mock.return_value = client
            valve.client = client

            with pytest.raises(ValveConnectionError, match="Required UART characteristics not found"):
                await valve.connect("1234")

    @pytest.mark.asyncio
    async def test_connect_authentication_failure(
        self, valve, mock_bleak_client, mock_hello_packet, mock_packet_parser
    ):
        """Test failed authentication during connect."""
        # Setup mocks for initial connection
        mock_bleak_client.connect.return_value = None
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [b"mock_packet"] * 2  # Need 2 packets (hello and auth response)
        valve.packet_queue = mock_queue

        # Setup packet parser responses - first hello packet and then unauthenticated hello packet
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        auth_response = MagicMock(spec=HelloPacket)
        auth_response.seed = 42
        auth_response.authenticated = False

        mock_packet_parser.parse.side_effect = [initial_hello, auth_response]

        # Mock login packet
        mock_login_packet = bytes([0x76] * 20)  # Example login packet
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login.return_value.generate.return_value = mock_login_packet

            result = await valve.connect("1234")

            assert result is False
            assert not valve.authenticated
            assert valve.connected is True  # Still connected, just not authenticated

            # Verify connection sequence
            mock_bleak_client.connect.assert_called_once()
            mock_bleak_client.start_notify.assert_called_once()

            # Verify packet writes
            assert mock_bleak_client.write_gatt_char.call_count == 2  # Hello and Login packets
            hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
            login_call = mock_bleak_client.write_gatt_char.call_args_list[1]
            assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet
            assert login_call.args[1] == mock_login_packet  # Login packet

            # Verify packet handling
            assert mock_queue.get.await_count == 2
            assert mock_packet_parser.parse.call_count == 2

    @pytest.mark.asyncio
    async def test_connect_timeout(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection timeout."""
        # Mock BleakClient to simulate successful connection
        mock_bleak_client.connect.return_value = None

        # Setup UART characteristics
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart = {
            NORDIC_UART_READ: mock_bleak_client.services[0].characteristics[0],
            NORDIC_UART_WRITE: write_char,
        }

        # Mock packet queue to simulate timeout immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = asyncio.TimeoutError("Timeout while waiting for initial hello packet")
        valve.packet_queue = mock_queue

        # Mock packet parser to never be called (due to timeout)
        mock_packet_parser.parse.return_value = None

        ret = await valve.connect("1234")
        assert ret is False

        # Verify connection sequence
        mock_bleak_client.connect.assert_called_once()
        mock_bleak_client.start_notify.assert_called_once()
        mock_packet_parser.parse.assert_not_called()

        # Should have attempted to write hello packet
        assert mock_bleak_client.write_gatt_char.call_count == 1
        hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
        assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet

    @pytest.mark.asyncio
    async def test_connect_invalid_password(self, valve, mock_bleak_client, mock_packet_parser, mock_hello_packet):
        """Test connection with invalid password format."""
        # Setup successful initial connection and hello packet
        mock_bleak_client.connect.return_value = None
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.return_value = b"mock_packet"
        valve.packet_queue = mock_queue

        # Setup initial hello packet
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False
        mock_packet_parser.parse.return_value = initial_hello

        # Mock the login packet creation to raise ValueError
        with patch("pycsmeter.valve._LoginPacket", autospec=True) as mock_login:
            mock_login.side_effect = ValueError("Invalid password format")

            with pytest.raises(ValueError, match="Invalid password format"):
                await valve.connect("invalid")

            # Verify connection sequence
            mock_bleak_client.connect.assert_called_once()
            mock_bleak_client.start_notify.assert_called_once()

            # Should have attempted to write the hello packet
            assert mock_bleak_client.write_gatt_char.call_count == 1
            hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
            assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet

            # Verify packet handling
            assert mock_queue.get.await_count == 1
            assert mock_packet_parser.parse.call_count == 1

    @pytest.mark.asyncio
    async def test_get_data_not_connected(self, valve):
        """Test getting data when not connected."""
        with pytest.raises(ValveConnectionError, match="Not connected"):
            await valve.get_data()

    @pytest.mark.asyncio
    async def test_get_data_not_authenticated(self, valve):
        """Test getting data when not authenticated."""
        valve.connected = True
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            await valve.get_data()

    @pytest.mark.asyncio
    async def test_get_data_success(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_water_usage_history_packet,
    ):
        """Test successful data retrieval."""
        try:
            # Setup UART characteristics
            read_char = mock_bleak_client.services[0].characteristics[0]
            write_char = mock_bleak_client.services[0].characteristics[1]
            valve.uart = {
                NORDIC_UART_READ: read_char,
                NORDIC_UART_WRITE: write_char
            }

            # Setup mock queue
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = [
                bytes([0x75] * 20),  # Dashboard packet
                bytes([0x75] * 20),  # Advanced packet
                bytes([0x75] * 20),  # History chunk 1
                bytes([0x75] * 20),  # History chunk 2
                bytes([0x75] * 20),  # History chunk 3
                bytes([0x75] * 20),  # History chunk 4
            ]
            valve.packet_queue = mock_queue

            # Mock packet parser responses
            mock_packet_parser.parse.side_effect = [
                mock_dashboard_packet,
                mock_advanced_packet,
                mock_water_usage_history_packet,
            ]

            # Set connected and authenticated state
            valve.connected = True
            valve.authenticated = True

            # Get data
            result = await valve.get_data()

            # Verify result
            assert isinstance(result, ValveData)
            assert result.dashboard is not None
            assert result.advanced is not None
            assert result.water_usage_history is not None

            # Verify queue gets
            assert mock_queue.get.await_count == 6

            # Verify all packets were parsed
            assert mock_packet_parser.parse.call_count == 3

            # Verify write operations
            mock_bleak_client.write_gatt_char.assert_called_once_with(
                write_char,
                bytes([0x75] * 20),  # Data request packet
                response=False,
            )

        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_timeout(self, valve, mock_bleak_client, mock_packet_parser):
        """Test data retrieval timeout."""
        try:
            valve.connected = True
            valve.authenticated = True
            valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

            # Mock packet queue to simulate timeout
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = asyncio.TimeoutError()
            valve.packet_queue = mock_queue

            mock_packet_parser.parse.side_effect = asyncio.TimeoutError()

            with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve"):
                await valve.get_data()
        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_retry_success(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_water_usage_history_packet,
    ):
        """Test successful retry after initial failure."""
        try:
            # Setup UART characteristics
            read_char = mock_bleak_client.services[0].characteristics[0]
            write_char = mock_bleak_client.services[0].characteristics[1]
            valve.uart = {
                NORDIC_UART_READ: read_char,
                NORDIC_UART_WRITE: write_char
            }

            # Create valid packet data - using correct hex values
            dashboard_bytes = bytes.fromhex("7575000000000000000000000000000000000000")  # Dashboard packet
            advanced_bytes = bytes.fromhex("7575010000000000000000000000000000000000")  # Advanced packet
            history_bytes = bytes.fromhex("7575020000000000000000000000000000000000")  # History packet

            # Setup mock queue
            mock_queue = AsyncMock()

            def queue_responses():
                # Will yield the same sequence for each attempt
                yield dashboard_bytes  # First attempt - dashboard
                yield advanced_bytes   # First attempt - advanced
                yield history_bytes    # First attempt - history chunk 1
                yield history_bytes    # First attempt - history chunk 2
                yield history_bytes    # First attempt - history chunk 3
                yield history_bytes    # First attempt - history chunk 4
                yield dashboard_bytes  # Second attempt - dashboard
                yield advanced_bytes   # Second attempt - advanced
                yield history_bytes    # Second attempt - history chunk 1
                yield history_bytes    # Second attempt - history chunk 2
                yield history_bytes    # Second attempt - history chunk 3
                yield history_bytes    # Second attempt - history chunk 4

            mock_queue.get.side_effect = queue_responses()
            valve.packet_queue = mock_queue

            # First attempt fails, second succeeds
            mock_packet_parser.parse.side_effect = [
                mock_dashboard_packet,  # First attempt - dashboard
                mock_advanced_packet,  # First attempt - advanced
                DataRetrievalError("First attempt fails"),  # First attempt - history fails
                mock_dashboard_packet,  # Second attempt - dashboard
                mock_advanced_packet,  # Second attempt - advanced
                mock_water_usage_history_packet,  # Second attempt - history (succeeds)
            ]

            # Set connected and authenticated state
            valve.connected = True
            valve.authenticated = True

            # Should succeed on second attempt
            result = await valve.get_data()

            # Verify result
            assert isinstance(result, ValveData)
            assert result.dashboard is not None
            assert result.advanced is not None
            assert result.water_usage_history is not None

            # Verify queue gets - 6 packets per attempt * 2 attempts
            assert mock_queue.get.await_count == 12

            # Verify packet parser calls - 3 packets per attempt * 2 attempts
            assert mock_packet_parser.parse.call_count == 6

            # Verify write operations - one per attempt
            assert mock_bleak_client.write_gatt_char.call_count == 2
            for call in mock_bleak_client.write_gatt_char.call_args_list:
                assert call == call(write_char, bytes([0x75] * 20), response=False)

        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_retry_with_sleep(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_water_usage_history_packet,
    ):
        """Test get_data retry with sleep between attempts."""
        try:
            # Setup UART characteristics
            read_char = mock_bleak_client.services[0].characteristics[0]
            write_char = mock_bleak_client.services[0].characteristics[1]
            valve.uart = {
                NORDIC_UART_READ: read_char,
                NORDIC_UART_WRITE: write_char
            }

            # Create valid packet data - using correct hex values
            dashboard_bytes = bytes.fromhex("7575000000000000000000000000000000000000")  # Dashboard packet
            advanced_bytes = bytes.fromhex("7575010000000000000000000000000000000000")  # Advanced packet
            history_bytes = bytes.fromhex("7575020000000000000000000000000000000000")  # History packet

            # Setup mock queue
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = [
                dashboard_bytes,  # First attempt - dashboard
                advanced_bytes,   # First attempt - advanced
                history_bytes,    # First attempt - history chunk 1
                history_bytes,    # First attempt - history chunk 2
                history_bytes,    # First attempt - history chunk 3
                history_bytes,    # First attempt - history chunk 4 (fails)
                dashboard_bytes,  # Second attempt - dashboard
                advanced_bytes,   # Second attempt - advanced
                history_bytes,    # Second attempt - history chunk 1
                history_bytes,    # Second attempt - history chunk 2
                history_bytes,    # Second attempt - history chunk 3
                history_bytes,    # Second attempt - history chunk 4 (succeeds)
            ]
            valve.packet_queue = mock_queue

            # First attempt fails, second succeeds after sleep
            mock_packet_parser.parse.side_effect = [
                mock_dashboard_packet,  # First attempt - dashboard
                mock_advanced_packet,  # First attempt - advanced
                DataRetrievalError("First attempt fails"),  # First attempt - history fails
                mock_dashboard_packet,  # Second attempt - dashboard
                mock_advanced_packet,  # Second attempt - advanced
                mock_water_usage_history_packet,  # Second attempt - history succeeds
            ]

            # Set connected and authenticated state
            valve.connected = True
            valve.authenticated = True

            # Setup sleep mock
            with patch("asyncio.sleep") as mock_sleep:
                # Should succeed on second attempt
                result = await valve.get_data()

                # Verify result
                assert isinstance(result, ValveData)
                assert result.dashboard is not None
                assert result.advanced is not None
                assert result.water_usage_history is not None

                # Verify sleep was called between attempts
                mock_sleep.assert_called_once_with(0.1)

                # Verify write operations - one per attempt
                assert mock_bleak_client.write_gatt_char.call_count == 2
                for call in mock_bleak_client.write_gatt_char.call_args_list:
                    assert call == call(write_char, bytes([0x75] * 20), response=False)

                # Verify queue operations - 12 packets total (6 per attempt)
                assert mock_queue.get.await_count == 12

                # Verify packet parser calls - 6 total (3 per attempt)
                assert mock_packet_parser.parse.call_count == 6

        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_success_first_try(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_water_usage_history_packet,
    ):
        """Test successful data retrieval on first try."""
        try:
            # Setup UART characteristics
            read_char = mock_bleak_client.services[0].characteristics[0]
            write_char = mock_bleak_client.services[0].characteristics[1]
            valve.uart = {
                NORDIC_UART_READ: read_char,
                NORDIC_UART_WRITE: write_char
            }

            # Create valid packet data - using correct hex values
            dashboard_bytes = bytes.fromhex("7575000000000000000000000000000000000000")  # Dashboard packet
            advanced_bytes = bytes.fromhex("7575010000000000000000000000000000000000")  # Advanced packet
            history_bytes = bytes.fromhex("7575020000000000000000000000000000000000")  # History packet

            # Setup mock queue
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = [
                dashboard_bytes,  # Dashboard packet
                advanced_bytes,   # Advanced packet
                history_bytes,    # History chunk 1
                history_bytes,    # History chunk 2
                history_bytes,    # History chunk 3
                history_bytes,    # History chunk 4
            ]
            valve.packet_queue = mock_queue

            def parser_responses():
                # Single successful attempt
                yield mock_dashboard_packet
                yield mock_advanced_packet
                yield mock_water_usage_history_packet

            mock_packet_parser.parse.side_effect = parser_responses()

            # Set connected and authenticated state
            valve.connected = True
            valve.authenticated = True

            # Should succeed on first try
            result = await valve.get_data()

            # Verify result
            assert isinstance(result, ValveData)
            assert result.dashboard is not None
            assert result.advanced is not None
            assert result.water_usage_history is not None

            # Verify queue gets - 6 packets for successful attempt
            assert mock_queue.get.await_count == 6

            # Verify packet parser calls - 3 packets for successful attempt
            assert mock_packet_parser.parse.call_count == 3

            # Verify write operations - one for successful attempt
            mock_bleak_client.write_gatt_char.assert_called_once_with(
                write_char,
                bytes([0x75] * 20),  # Data request packet
                response=False,
            )

        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_cleanup(self, valve, mock_bleak_client):
        """Test disconnect cleans up state properly (line 187)."""
        try:
            # Setup initial state
            valve.connected = True
            valve.authenticated = True
            valve.uart = {
                NORDIC_UART_READ: mock_bleak_client.services[0].characteristics[0],
                NORDIC_UART_WRITE: mock_bleak_client.services[0].characteristics[1],
            }

            # Disconnect
            await valve.disconnect()

            # Verify state is cleaned up
            assert not valve.connected
            assert not valve.authenticated
            mock_bleak_client.disconnect.assert_called_once()
        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_not_connected_error(self, valve):
        """Test get_data raises error when not connected (line 114)."""
        valve.connected = False
        with pytest.raises(ValveConnectionError, match="Not connected to valve"):
            await valve.get_data()

    @pytest.mark.asyncio
    async def test_connect_hello_packet_timeout(self, valve, mock_bleak_client):
        """Test connect handling hello packet timeout (line 161)."""
        # Setup UART characteristics
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock queue to timeout
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = asyncio.TimeoutError()
        valve.packet_queue = mock_queue

        # Should return False on timeout
        result = await valve.connect("1234")
        assert result is False

    @pytest.mark.asyncio
    async def test_connect_invalid_hello_packet(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connect handling invalid hello packet type (line 167)."""
        # Setup UART characteristics
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock queue to return data
        mock_queue = AsyncMock()
        mock_queue.get.return_value = bytes([0] * 20)
        valve.packet_queue = mock_queue

        # Mock parser to return wrong packet type
        mock_packet_parser.parse.return_value = InvalidPacket()

        # Should return False on invalid packet
        result = await valve.connect("1234")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_data_retry_with_validation_error(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet
    ):
        """Test get_data retry with validation error (lines 179-275)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create valid packet data - using correct hex values
        # Each packet has 3 header bytes (0x75, 0x75, type) followed by 17 bytes payload
        dashboard_bytes = bytes.fromhex("757500") + bytes([0] * 17)  # Dashboard packet (20 bytes)
        advanced_bytes = bytes.fromhex("757501") + bytes([0] * 17)   # Advanced packet (20 bytes)
        history_chunk1 = bytes.fromhex("757502") + bytes([0] * 17)   # History chunk 1 (20 bytes)
        history_chunk2 = bytes([0] * 20)   # History chunk 2 (20 bytes)
        history_chunk3 = bytes([0] * 20)   # History chunk 3 (20 bytes)
        history_chunk4 = bytes([0] * 5)    # History chunk 4 (5 bytes)
        invalid_bytes = bytes([0] * 20)  # Invalid packet

        # Mock queue to return data
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,  # First attempt - dashboard
            advanced_bytes,   # First attempt - advanced
            invalid_bytes,    # First attempt - history chunk 1 (fails)
            invalid_bytes,    # First attempt - history chunk 2 (fails)
            invalid_bytes,    # First attempt - history chunk 3 (fails)
            invalid_bytes,    # First attempt - history chunk 4 (fails)
            dashboard_bytes,  # Second attempt - dashboard
            advanced_bytes,   # Second attempt - advanced
            history_chunk1,   # Second attempt - history chunk 1
            history_chunk2,   # Second attempt - history chunk 2
            history_chunk3,   # Second attempt - history chunk 3
            history_chunk4,   # Second attempt - history chunk 4
        ]
        valve.packet_queue = mock_queue

        # Mock parser to fail first attempt with validation error
        mock_packet_parser.parse.side_effect = [
            mock_dashboard_packet,                    # First attempt - dashboard
            mock_advanced_packet,                     # First attempt - advanced
            PacketValidationError("Invalid packet"),  # First attempt - history fails
            mock_dashboard_packet,                    # Second attempt - dashboard
            mock_advanced_packet,                     # Second attempt - advanced
            mock_water_usage_history_packet,          # Second attempt - history succeeds
        ]

        with patch("asyncio.sleep") as mock_sleep:
            result = await valve.get_data()
            assert isinstance(result, ValveData)
            mock_sleep.assert_called_once_with(0.1)

            # Verify queue operations - 12 packets total (6 per attempt)
            assert mock_queue.get.await_count == 12

            # Verify packet parser calls - 6 total (3 per attempt)
            assert mock_packet_parser.parse.call_count == 6

            # Verify write operations - one per attempt
            assert mock_bleak_client.write_gatt_char.call_count == 2
            for call in mock_bleak_client.write_gatt_char.call_args_list:
                assert call == call(mock_bleak_client.services[0].characteristics[1], bytes([0x75] * 20), response=False)

    @pytest.mark.asyncio
    async def test_get_data_timeout_error(self, valve, mock_bleak_client):
        """Test get_data handling timeout error (line 308)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock queue to timeout
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = asyncio.TimeoutError()
        valve.packet_queue = mock_queue

        with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve"):
            await valve.get_data()

    @pytest.mark.asyncio
    async def test_get_data_invalid_packet_type(self, valve, mock_bleak_client, mock_packet_parser):
        """Test get_data handling invalid packet type (line 315)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock queue to return data
        mock_queue = AsyncMock()
        mock_queue.get.return_value = bytes([0] * 20)
        valve.packet_queue = mock_queue

        # Mock parser to return wrong packet type
        mock_packet_parser.parse.return_value = InvalidPacket()

        with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve"):
            await valve.get_data()

    @pytest.mark.asyncio
    async def test_get_data_water_usage_history_chunks(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet
    ):
        """Test get_data collecting water usage history chunks."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create valid packet data
        dashboard_bytes = bytes.fromhex("757500") + bytes([0] * 17)  # Dashboard packet (20 bytes)
        advanced_bytes = bytes.fromhex("757501") + bytes([0] * 17)   # Advanced packet (20 bytes)
        water_usage_history_chunk1 = bytes.fromhex("757502") + bytes([0] * 17)   # First history chunk (20 bytes)
        water_usage_history_chunk2 = bytes([0] * 20)                             # Second history chunk (20 bytes)
        water_usage_history_chunk3 = bytes([0] * 20)                             # Third history chunk (20 bytes)
        water_usage_history_chunk4 = bytes([0] * 5)                              # Fourth history chunk (5 bytes)

        # Mock packet queue to return packets in sequence
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,
            advanced_bytes,
            water_usage_history_chunk1,
            water_usage_history_chunk2,
            water_usage_history_chunk3,
            water_usage_history_chunk4,
        ]

        # Mock packet parser to return our mock packets
        mock_packet_parser.parse.side_effect = [
            mock_dashboard_packet,
            mock_advanced_packet,
            mock_water_usage_history_packet,
        ]

        valve.packet_queue = mock_queue

        # Get the data
        result = await valve._Valve__get_data()
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_water_usage_history_packet)

        print(result.dashboard)
        print(valve_data)

        # Verify the result by comparing specific attributes
        assert result.dashboard == valve_data.dashboard
        assert result.advanced == valve_data.advanced
        assert result.water_usage_history == valve_data.water_usage_history

        # Verify the packets were parsed correctly
        assert mock_packet_parser.parse.call_count == 3

    @pytest.mark.asyncio
    async def test_connect_to_valve_missing_characteristics(self, valve, mock_bleak_client):
        """Test connect_to_valve handling missing characteristics (line 374)."""
        # Remove characteristics from mock service
        mock_bleak_client.services[0].characteristics = []

        with pytest.raises(ValveConnectionError, match="Required UART characteristics not found"):
            await valve._Valve__connect_to_valve()

    @pytest.mark.asyncio
    async def test_connect_invalid_hello_after_login(self, valve, mock_bleak_client, mock_packet_parser):
        """Test handling invalid hello packet response after sending login packet."""
        # Setup UART write characteristic
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_WRITE] = write_char
        valve.connected = False

        # Mock packet queue to return both hello packets
        mock_queue = AsyncMock()
        # Create valid hello packet format: first two bytes 0x74, third byte 0x00
        hello_packet = bytes([0x74, 0x74, 0x00] + [0] * 17)  # 20 bytes total
        invalid_packet = bytes([0x75, 0x75, 0x00] + [0] * 17)  # Wrong packet type
        mock_queue.get.side_effect = [
            hello_packet,    # Initial hello packet before login
            invalid_packet,  # Invalid packet type after login
        ]
        valve.packet_queue = mock_queue

        # Mock parser to handle both packets
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        second_hello = MagicMock(spec=InvalidPacket)

        mock_packet_parser.parse.side_effect = [
            initial_hello,  # First parse returns valid hello packet
            second_hello,   # Second parse returns invalid packet
        ]

        # Mock login packet generation
        test_login_packet = bytes([0x74, 0x74, 0x00] + [0] * 17)  # Valid login packet format
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login_instance = MagicMock()
            mock_login_instance.generate.return_value = test_login_packet
            mock_login.return_value = mock_login_instance

            # Test authentication with invalid response
            with pytest.raises(PacketValidationError, match="Expected HelloPacket but received"):
                await valve.connect("1234")

            # Verify failure
            assert valve.authenticated is False

            # Verify login packet was created and sent
            mock_login.assert_called_once_with(42, "1234")
            mock_login_instance.generate.assert_called_once()

            # Verify all packets were sent
            assert mock_bleak_client.write_gatt_char.call_count == 2

            # Verify both responses were processed
            assert mock_queue.get.await_count == 2
            assert mock_packet_parser.parse.call_count == 2

    @pytest.mark.asyncio
    async def test_connect_timeout_while_hello(self, valve, mock_bleak_client, mock_packet_parser):
        """Test handling invalid hello packet response after sending login packet."""
        # Setup UART write characteristic
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_WRITE] = write_char
        valve.connected = False

        # Mock packet queue to return both hello packets
        mock_queue = AsyncMock()
        # Create valid hello packet format: first two bytes 0x74, third byte 0x00
        hello_packet = bytes([0x74, 0x74, 0x00] + [0] * 17)  # 20 bytes total
        invalid_packet = bytes([0x75, 0x75, 0x00] + [0] * 17)  # Wrong packet type
        mock_queue.get.side_effect = [
            hello_packet,    # Initial hello packet before login
            invalid_packet,  # Invalid packet type after login
        ]
        valve.packet_queue = mock_queue

        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        mock_packet_parser.parse.side_effect = [
            initial_hello,
            asyncio.TimeoutError(),  # Simulate timeout error
        ]

        # Mock login packet generation
        test_login_packet = bytes([0x74, 0x74, 0x00] + [0] * 17)  # Valid login packet format
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login_instance = MagicMock()
            mock_login_instance.generate.return_value = test_login_packet
            mock_login.return_value = mock_login_instance

            # Test authentication with invalid response
            connected = await valve.connect("1234")
            assert connected is False

    @pytest.mark.asyncio
    async def test_get_data_invalid_water_usage_history_packet_type(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet,
    ):
        """Test handling invalid water usage history packet type in __get_data (line 318)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create valid packet data
        dashboard_bytes = bytes([0x75, 0x75, 0x00] + [0] * 17)  # Dashboard packet
        advanced_bytes = bytes([0x75, 0x75, 0x01] + [0] * 17)   # Advanced packet
        water_usage_history_chunk1 = bytes([0x75, 0x75, 0x02] + [0] * 17)   # History chunk 1
        water_usage_history_chunk2 = bytes([0] * 20)   # History chunk 2
        water_usage_history_chunk3 = bytes([0] * 20)   # History chunk 3
        water_usage_history_chunk4 = bytes([0] * 5)    # History chunk 4

        # Mock queue to return packets
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
        ]
        valve.packet_queue = mock_queue

        # Mock parser to return wrong type for water usage history packet
        mock_wrong_type = MagicMock(spec=DashboardPacket)  # Wrong packet type
        mock_packet_parser.parse.side_effect = [
            mock_dashboard_packet,  # First parse returns dashboard packet
            mock_advanced_packet,   # Second parse returns advanced packet
            mock_wrong_type,        # Third parse returns wrong packet type
            mock_dashboard_packet,  # Need to repeat 3 times due to retry logic
            mock_advanced_packet,   
            mock_wrong_type,   
            mock_dashboard_packet,
            mock_advanced_packet,
            mock_wrong_type,
        ]

        # Test data retrieval with wrong packet type
        with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve"):
            await valve.get_data()

        # Verify queue operations - should process first packet and fail on second
        assert mock_queue.get.await_count == 18
        assert mock_packet_parser.parse.call_count == 9

    @pytest.mark.asyncio
    async def test_get_data_invalid_advanced_packet_type(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_water_usage_history_packet,
    ):
        """Test handling invalid water usage history packet type in __get_data (line 318)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create valid packet data
        dashboard_bytes = bytes([0x75, 0x75, 0x00] + [0] * 17)  # Dashboard packet
        advanced_bytes = bytes([0x75, 0x75, 0x01] + [0] * 17)   # Advanced packet
        water_usage_history_chunk1 = bytes([0x75, 0x75, 0x02] + [0] * 17)   # History chunk 1
        water_usage_history_chunk2 = bytes([0] * 20)   # History chunk 2
        water_usage_history_chunk3 = bytes([0] * 20)   # History chunk 3
        water_usage_history_chunk4 = bytes([0] * 5)    # History chunk 4

        # Mock queue to return packets
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
            dashboard_bytes,  # Dashboard packet
            advanced_bytes,   # Advanced packet
            water_usage_history_chunk1,   # History chunk 1
            water_usage_history_chunk2,   # History chunk 2
            water_usage_history_chunk3,   # History chunk 3
            water_usage_history_chunk4,   # History chunk 4
        ]
        valve.packet_queue = mock_queue

        # Mock parser to return wrong type for water usage history packet
        mock_wrong_type = MagicMock(spec=DashboardPacket)  # Wrong packet type
        mock_packet_parser.parse.side_effect = [
            mock_dashboard_packet,  # First parse returns dashboard packet
            mock_wrong_type,   # Second parse returns advanced packet
            mock_water_usage_history_packet,        # Third parse returns wrong packet type
            mock_dashboard_packet,  # Need to repeat 3 times due to retry logic
            mock_wrong_type,   
            mock_water_usage_history_packet,   
            mock_dashboard_packet,
            mock_wrong_type,
            mock_water_usage_history_packet,
        ]

        # Test data retrieval with wrong packet type
        with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve"):
            await valve.get_data()

        # Verify queue operations - should process first packet and fail on second
        assert mock_queue.get.await_count == 5
        assert mock_packet_parser.parse.call_count == 5
