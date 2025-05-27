"""Tests for the valve module."""

import asyncio
from datetime import date
from unittest.mock import AsyncMock, MagicMock, call, patch
import warnings

import pytest
import pytest_asyncio
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from pycsmeter._packets import (
    AdvancedPacket,
    DashboardPacket,
    EmptyPacket,
    HelloPacket,
    HistoryPacket,
    InvalidPacket,
    LoginPacket,
)
from pycsmeter._packets import (
    HistoryItem as _HistoryItem,
)
from pycsmeter.exceptions import (
    AuthenticationError,
    DataRetrievalError,
    PacketValidationError,
    ValveConnectionError,
)
from pycsmeter.valve import (
    NORDIC_UART_READ,
    NORDIC_UART_WRITE,
    AdvancedData,
    DashboardData,
    HistoryItem,
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
    """Create a mock DashboardPacket."""
    packet = MagicMock(spec=DashboardPacket)
    packet.hour = 14
    packet.minute = 30
    packet.battery_volt = 3.3
    packet.current_flow = 5.5
    packet.soft_remaining = 1000
    packet.treated_usage_today = 50
    packet.peak_flow_today = 7.5
    packet.water_hardness = 15
    packet.regen_hour = 2
    return packet


@pytest.fixture
def mock_advanced_packet():
    """Create a mock AdvancedPacket."""
    packet = MagicMock(spec=AdvancedPacket)
    packet.regen_days = 7
    packet.days_to_regen = 3
    return packet


@pytest.fixture
def mock_history_packet():
    """Create a mock HistoryPacket."""
    today = date.today()
    items = [
        _HistoryItem(item_date=today, gallon_per_day=100.0),
        _HistoryItem(item_date=today, gallon_per_day=150.0),
    ]
    packet = MagicMock(spec=HistoryPacket)
    packet.history_gallons_per_day = items
    return packet


@pytest_asyncio.fixture
async def mock_packet_parser():
    """Create a mock PacketParser."""
    parser = AsyncMock()
    parser.parse_packet = AsyncMock()
    return parser


@pytest.fixture(autouse=True)
def ignore_unraisable_warning():
    """Ignore PytestUnraisableExceptionWarning warnings."""
    warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)
    yield


class TestValveData:
    """Tests for the ValveData class."""

    def test_from_internal(self, mock_dashboard_packet, mock_advanced_packet, mock_history_packet):
        """Test converting internal packet types to ValveData."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_history_packet)

        assert isinstance(valve_data.dashboard, DashboardData)
        assert valve_data.dashboard.hour == 14
        assert valve_data.dashboard.minute == 30
        assert valve_data.dashboard.battery_voltage == 3.3
        assert valve_data.dashboard.current_flow == 5.5
        assert valve_data.dashboard.soft_water_remaining == 1000
        assert valve_data.dashboard.treated_usage_today == 50
        assert valve_data.dashboard.peak_flow_today == 7.5
        assert valve_data.dashboard.water_hardness == 15
        assert valve_data.dashboard.regeneration_hour == 2

        assert isinstance(valve_data.advanced, AdvancedData)
        assert valve_data.advanced.regeneration_days == 7
        assert valve_data.advanced.days_to_regeneration == 3

        assert len(valve_data.history) == 2
        assert all(isinstance(item, HistoryItem) for item in valve_data.history)
        assert valve_data.history[0].gallons_per_day == 100.0
        assert valve_data.history[1].gallons_per_day == 150.0

    def test_get_history_for_date(self, mock_dashboard_packet, mock_advanced_packet, mock_history_packet):
        """Test retrieving history for a specific date."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_history_packet)
        today = date.today()

        history_item = valve_data.get_history_for_date(today)
        assert history_item is not None
        assert history_item.item_date == today
        assert history_item.gallons_per_day == 100.0

        # Test non-existent date
        assert valve_data.get_history_for_date(date(2000, 1, 1)) is None

    def test_get_history_last_n_days(self, mock_dashboard_packet, mock_advanced_packet, mock_history_packet):
        """Test retrieving last N days of history."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_history_packet)

        history = valve_data.get_history_last_n_days(1)
        assert len(history) == 1
        assert history[0].gallons_per_day == 100.0

        history = valve_data.get_history_last_n_days(2)
        assert len(history) == 2
        assert history[0].gallons_per_day == 100.0
        assert history[1].gallons_per_day == 150.0

    def test_get_history_last_n_days_exceeds_available(
        self, mock_dashboard_packet, mock_advanced_packet, mock_history_packet
    ):
        """Test requesting more history days than available."""
        valve_data = ValveData.from_internal(mock_dashboard_packet, mock_advanced_packet, mock_history_packet)

        history = valve_data.get_history_last_n_days(10)  # More than available
        assert len(history) == 2  # Should return all available


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
        self, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet, mock_history_packet
    ):
        """Test get_data retry logic for getting data."""
        valve = await self.setup_valve_with_client(mock_bleak_client)
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create valid packet data - using correct hex values
        dashboard_bytes = bytes.fromhex("7575000000000000000000000000000000000000")  # Dashboard packet
        advanced_bytes = bytes.fromhex("7575010000000000000000000000000000000000")  # Advanced packet
        history_bytes = bytes.fromhex("7575020000000000000000000000000000000000")  # History packet
        history_invalid_bytes = bytes.fromhex("757502000000")  # Invalid History packet
        empty_bytes = bytes.fromhex("7000000000000000000000000000000000000000")  # Empty packet

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            dashboard_bytes,  # First attempt - dashboard
            advanced_bytes,  # First attempt - advanced
            history_invalid_bytes,  # First attempt - history
            history_invalid_bytes,  # First attempt - history
            dashboard_bytes,  # Second attempt - dashboard
            advanced_bytes,  # Second attempt - advanced
            history_bytes,  # Second attempt - empty1
            history_bytes,  # Second attempt - empty2
            history_bytes,  # Second attempt - empty3
            history_bytes,  # Second attempt - history
        ]
        valve.packet_queue = mock_queue

        # First attempt fails, second succeeds
        mock_packet_parser.parse_packet.side_effect = [
            mock_dashboard_packet,  # First attempt - dashboard
            mock_advanced_packet,  # First attempt - advanced
            EOFError("First attempt fails"),  # First attempt - empty1 fails
            mock_dashboard_packet,  # Second attempt - dashboard
            mock_advanced_packet,  # Second attempt - advanced
            EmptyPacket(),  # Second attempt - empty1
            EmptyPacket(),  # Second attempt - empty2
            EmptyPacket(),  # Second attempt - empty3
            mock_history_packet,  # Second attempt - history
        ]

        with patch("asyncio.sleep") as mock_sleep:
            result = await valve.get_data()
            mock_sleep.assert_called_once()

        assert isinstance(result, ValveData)
        assert mock_bleak_client.write_gatt_char.call_count == 2  # Initial request + retry

        # Verify queue operations - 10 packets total
        assert mock_queue.get.await_count == 10

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
            # Setup mocks for successful connection
            mock_bleak_client.connect.return_value = None
            valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

            # Mock packet queue to return data immediately
            mock_data = AsyncMock()
            mock_data.side_effect = [b"mock_packet"] * 2  # Need 2 packets (hello and auth response)
            valve.packet_queue.get = mock_data

            # Setup packet parser responses - first hello packet and then authenticated hello packet
            hello_response = MagicMock(spec=HelloPacket)
            hello_response.seed = 42
            hello_response.authenticated = True
            mock_packet_parser.parse_packet.side_effect = [hello_response, hello_response]

            # Mock login packet
            mock_login_packet = bytes([0x76] * 20)  # Example login packet
            with patch("pycsmeter.valve._LoginPacket") as mock_login:
                mock_login.return_value.generate.return_value = mock_login_packet

                result = await valve.connect("1234")

                assert result is True
                assert valve.authenticated is True
                assert valve.connected is True

                # Verify connection sequence
                mock_bleak_client.connect.assert_called_once()
                mock_bleak_client.start_notify.assert_called_once()

                # Verify UART setup
                assert len(valve.uart) == 2
                assert NORDIC_UART_READ in valve.uart
                assert NORDIC_UART_WRITE in valve.uart

                # Verify packet writes
                assert mock_bleak_client.write_gatt_char.call_count == 2  # Hello and Login packets
                hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
                login_call = mock_bleak_client.write_gatt_char.call_args_list[1]
                assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet
                assert login_call.args[1] == mock_login_packet  # Login packet

                # Verify packet handling
                assert valve.packet_queue.get.await_count == 2
                assert mock_packet_parser.parse_packet.call_count == 2
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

        mock_packet_parser.parse_packet.side_effect = [initial_hello, auth_response]

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
            assert mock_packet_parser.parse_packet.call_count == 2

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
        mock_packet_parser.parse_packet.return_value = None

        with pytest.raises(DataRetrievalError, match="Timeout while waiting for initial hello packet"):
            await valve.connect("1234")

        # Verify connection sequence
        mock_bleak_client.connect.assert_called_once()
        mock_bleak_client.start_notify.assert_called_once()
        mock_packet_parser.parse_packet.assert_not_called()

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
        mock_packet_parser.parse_packet.return_value = initial_hello

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
            assert mock_packet_parser.parse_packet.call_count == 1

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
        mock_history_packet,
    ):
        """Test successful data retrieval."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [b"mock_packet"] * 6  # Need 6 packets total
        valve.packet_queue = mock_queue

        # Mock packet parser responses
        mock_packet_parser.parse_packet.side_effect = [
            mock_dashboard_packet,
            mock_advanced_packet,
            EmptyPacket(),
            EmptyPacket(),
            EmptyPacket(),
            mock_history_packet,
        ]

        result = await valve.get_data()

        assert isinstance(result, ValveData)
        assert isinstance(result.dashboard, DashboardData)
        assert isinstance(result.advanced, AdvancedData)
        assert len(result.history) == 2

        # Verify data request packet was sent
        mock_bleak_client.write_gatt_char.assert_called_with(
            valve.uart[NORDIC_UART_WRITE],
            bytes([0x75] * 20),
            response=False,
        )

        # Verify all packets were requested
        assert mock_queue.get.await_count == 6
        # Verify all packets were parsed
        assert mock_packet_parser.parse_packet.call_count == 6

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

            mock_packet_parser.parse_packet.side_effect = asyncio.TimeoutError()

            with pytest.raises(DataRetrievalError, match="Timeout while waiting for packets"):
                await valve.get_data()
        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_get_data_invalid_packet_types(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet
    ):
        """Test get_data with invalid packet types (lines 194, 199)."""
        try:
            valve.connected = True
            valve.authenticated = True
            valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

            # Test cases: (response_packets, expected_error_message)
            test_cases = [
                # First case: Empty packet when expecting dashboard
                ([EmptyPacket()], "Expected DashboardPacket but received EmptyPacket"),
                # Second case: Empty packet when expecting advanced after dashboard
                ([mock_dashboard_packet, EmptyPacket()], "Expected AdvancedPacket but received EmptyPacket"),
                # Third case: Invalid history packet after EmptyPackets
                (
                    [
                        mock_dashboard_packet,
                        mock_advanced_packet,
                        EmptyPacket(),
                        EmptyPacket(),
                        EmptyPacket(),
                        EmptyPacket(),
                    ],
                    "Expected HistoryPacket but received EmptyPacket",
                ),
            ]

            for response_packets, error_msg in test_cases:
                # Reset mocks for each test case
                mock_bleak_client.reset_mock()
                mock_packet_parser.reset_mock()

                # Create new mock queue for each test case
                mock_queue = AsyncMock()
                # Create a list of mock packet bytes matching the length of response_packets
                mock_queue.get.side_effect = [b"mock_packet" for _ in range(len(response_packets))]
                valve.packet_queue = mock_queue

                # Setup packet parser responses for this test case
                mock_packet_parser.parse_packet.side_effect = response_packets

                # Should raise PacketValidationError
                with pytest.raises(PacketValidationError, match=error_msg):
                    await valve.get_data()

                # Verify data request was sent exactly once for this test case
                mock_bleak_client.write_gatt_char.assert_called_once()
                data_request = mock_bleak_client.write_gatt_char.call_args
                assert data_request.args[1] == bytes([0x75] * 20)
                assert data_request.kwargs["response"] is False

                # Verify queue operations match the number of packets we actually read
                assert mock_queue.get.await_count == len(response_packets)

                # Verify packet parser calls match the number of packets we actually read
                assert mock_packet_parser.parse_packet.call_count == len(response_packets)
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
        mock_history_packet,
    ):
        """Test successful data retrieval after retries."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue to return data immediately
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [b"mock_packet"] * 9
        valve.packet_queue = mock_queue

        # First attempt fails, second succeeds
        mock_packet_parser.parse_packet.side_effect = [
            mock_dashboard_packet,  # First attempt fails
            mock_advanced_packet,
            mock_advanced_packet,  # First attempt fails
            mock_dashboard_packet,  # Second attempt succeeds
            mock_advanced_packet,
            EmptyPacket(),
            EmptyPacket(),
            EmptyPacket(),
            mock_history_packet,
        ]

        result = await valve.get_data()
        assert isinstance(result, ValveData)

        # Verify data request packets were sent (initial + retry)
        assert mock_bleak_client.write_gatt_char.call_count == 2
        for call in mock_bleak_client.write_gatt_char.call_args_list:
            assert call.args[1] == bytes([0x75] * 20)  # Data request packet
            assert call.kwargs["response"] is False

    def test_notification_handler(self, valve):
        """Test the BLE notification handler."""
        test_data = bytearray(b"test_data")
        valve._notification_handler(None, test_data)

        # Verify data was put in queue
        received_data = valve.packet_queue.get_nowait()
        assert received_data == test_data

    @pytest.mark.asyncio
    async def test_connect_wrong_packet_type(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection with wrong packet type response."""
        # Setup mocks
        mock_bleak_client.connect.return_value = None
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue
        mock_queue = AsyncMock()
        mock_queue.get.return_value = b"mock_packet"
        valve.packet_queue = mock_queue

        # Return wrong packet type
        mock_packet_parser.parse_packet.return_value = EmptyPacket()

        with pytest.raises(PacketValidationError, match="Expected initial HelloPacket"):
            await valve.connect("1234")

    @pytest.mark.asyncio
    async def test_connect_cleanup_after_error(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection cleanup after error."""
        # Setup mocks
        mock_bleak_client.connect.return_value = None
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Simulate error during connection
        mock_bleak_client.start_notify.side_effect = Exception("Connection error")

        with pytest.raises(Exception, match="Connection error"):
            await valve.connect("1234")

    @pytest.mark.asyncio
    async def test_get_data_retry_with_sleep(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_history_packet,
    ):
        """Test data retrieval with sleep between retries."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Mock packet queue
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [b"mock_packet"] * 13  # Need packets for two attempts
        valve.packet_queue = mock_queue

        # First attempt fails, second succeeds after sleep
        mock_packet_parser.parse_packet.side_effect = [EOFError("First attempt")] + [  # First attempt fails
            mock_dashboard_packet,  # Second attempt succeeds
            mock_advanced_packet,
            EmptyPacket(),
            EmptyPacket(),
            EmptyPacket(),
            mock_history_packet,
        ]

        with patch("asyncio.sleep") as mock_sleep:
            result = await valve.get_data()
            mock_sleep.assert_called_once()

        assert isinstance(result, ValveData)

    @pytest.mark.asyncio
    async def test_connect_missing_uart_characteristics(self, valve, mock_bleak_client):
        """Test connection with missing UART characteristics."""
        try:
            mock_bleak_client.connect.return_value = None

            # Test missing read characteristic
            read_service = MagicMock()
            write_char = MagicMock(spec=BleakGATTCharacteristic)
            write_char.uuid = str(NORDIC_UART_WRITE)
            read_service.characteristics = [write_char]
            mock_bleak_client.services = [read_service]

            with pytest.raises(
                ValveConnectionError, match="Required UART characteristics not found.*notify \\(read\\)"
            ):
                await valve.connect("1234")

            await valve.disconnect()

            # Test missing write characteristic
            read_char = MagicMock(spec=BleakGATTCharacteristic)
            read_char.uuid = str(NORDIC_UART_READ)
            read_service.characteristics = [read_char]

            with pytest.raises(ValveConnectionError, match="Required UART characteristics not found.*write"):
                await valve.connect("1234")

            await valve.disconnect()

            # Test missing both characteristics
            read_service.characteristics = []

            with pytest.raises(
                ValveConnectionError, match="Required UART characteristics not found.*notify \\(read\\), write"
            ):
                await valve.connect("1234")
        finally:
            # Ensure cleanup even if test fails
            if valve.connected:
                await valve.disconnect()

    @pytest.mark.asyncio
    async def test_connect_no_hello_packet(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection when no hello packet is received."""
        # Setup successful BLE connection
        mock_bleak_client.connect.return_value = None

        # Setup UART characteristics
        read_char = mock_bleak_client.services[0].characteristics[0]
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_READ] = read_char
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock packet queue to never return data (simulating no response)
        mock_queue = AsyncMock()
        mock_queue.get = AsyncMock(side_effect=asyncio.TimeoutError("No hello packet received"))
        valve.packet_queue = mock_queue

        # Mock packet parser to never be called (due to timeout)
        mock_packet_parser.parse_packet.return_value = None

        # Attempt connection - should raise DataRetrievalError
        with pytest.raises(
            DataRetrievalError, match="Timeout while waiting for initial hello packet.*15s timeout exceeded"
        ):
            await valve.connect("1234")

        # Verify connection sequence
        mock_bleak_client.connect.assert_called_once()
        mock_bleak_client.start_notify.assert_called_once()
        mock_packet_parser.parse_packet.assert_not_called()

        # Verify hello packet was sent
        mock_bleak_client.write_gatt_char.assert_called_once_with(
            write_char,
            bytes([0x74] * 20),  # Hello packet
            response=False,
        )

        # Verify queue was attempted to be read with timeout
        mock_queue.get.assert_awaited_once()

        # Verify valve state
        assert valve.connected  # Should still be connected at BLE level
        assert not valve.authenticated  # But not authenticated

    @pytest.mark.asyncio
    async def test_connect_wrong_packet_type_after_login(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection when receiving wrong packet type after login."""
        # Setup successful BLE connection
        mock_bleak_client.connect.return_value = None

        # Setup UART characteristics
        read_char = mock_bleak_client.services[0].characteristics[0]
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_READ] = read_char
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock packet queue for initial hello and login response
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            b"initial_hello",  # First hello packet
            b"invalid_login_response",  # Login response
        ]
        valve.packet_queue = mock_queue

        # Setup initial hello packet
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        # Mock packet parser to return hello packet first, then invalid packet type
        mock_packet_parser.parse_packet.side_effect = [
            initial_hello,  # Initial hello
            EmptyPacket(),  # Wrong packet type after login
        ]

        # Mock login packet generation
        mock_login_packet = bytes([0x76] * 20)
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login.return_value.generate.return_value = mock_login_packet

            # Attempt connection - should raise PacketValidationError
            with pytest.raises(PacketValidationError, match="Expected HelloPacket but received EmptyPacket"):
                await valve.connect("1234")

            # Verify connection and packet sequence
            mock_bleak_client.connect.assert_called_once()
            mock_bleak_client.start_notify.assert_called_once()

            # Verify both hello and login packets were sent
            assert mock_bleak_client.write_gatt_char.call_count == 2
            hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
            login_call = mock_bleak_client.write_gatt_char.call_args_list[1]
            assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet
            assert login_call.args[1] == mock_login_packet  # Login packet

            # Verify queue was read twice
            assert mock_queue.get.await_count == 2

            # Verify packet parser was called twice
            assert mock_packet_parser.parse_packet.call_count == 2

            # Verify valve state
            assert valve.connected  # Should still be connected at BLE level
            assert not valve.authenticated  # But not authenticated

    @pytest.mark.asyncio
    async def test_connect_unauthenticated_after_login(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection when receiving unauthenticated hello packet after login."""
        # Setup successful BLE connection
        mock_bleak_client.connect.return_value = None

        # Setup UART characteristics
        read_char = mock_bleak_client.services[0].characteristics[0]
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_READ] = read_char
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock packet queue for initial hello and login response
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            b"initial_hello",  # First hello packet
            b"login_response",  # Login response
        ]
        valve.packet_queue = mock_queue

        # Setup hello packets
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        login_response = MagicMock(spec=HelloPacket)
        login_response.seed = 42
        login_response.authenticated = False  # Still not authenticated

        # Mock packet parser to return hello packets
        mock_packet_parser.parse_packet.side_effect = [
            initial_hello,  # Initial hello
            login_response,  # Login response (unauthenticated)
        ]

        # Mock login packet generation
        mock_login_packet = bytes([0x76] * 20)
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login.return_value.generate.return_value = mock_login_packet

            # Attempt connection - should return False
            result = await valve.connect("1234")
            assert result is False

            # Verify connection and packet sequence
            mock_bleak_client.connect.assert_called_once()
            mock_bleak_client.start_notify.assert_called_once()

            # Verify both hello and login packets were sent
            assert mock_bleak_client.write_gatt_char.call_count == 2
            hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
            login_call = mock_bleak_client.write_gatt_char.call_args_list[1]
            assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet
            assert login_call.args[1] == mock_login_packet  # Login packet

            # Verify queue was read twice
            assert mock_queue.get.await_count == 2

            # Verify packet parser was called twice
            assert mock_packet_parser.parse_packet.call_count == 2

            # Verify valve state
            assert valve.connected  # Should still be connected at BLE level
            assert not valve.authenticated  # But not authenticated

    @pytest.mark.asyncio
    async def test_connect_login_timeout(self, valve, mock_bleak_client, mock_packet_parser):
        """Test connection when login response times out."""
        # Setup successful BLE connection
        mock_bleak_client.connect.return_value = None

        # Setup UART characteristics
        read_char = mock_bleak_client.services[0].characteristics[0]
        write_char = mock_bleak_client.services[0].characteristics[1]
        valve.uart[NORDIC_UART_READ] = read_char
        valve.uart[NORDIC_UART_WRITE] = write_char

        # Mock packet queue to return initial hello but timeout on login response
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = [
            b"initial_hello",  # First hello packet
            asyncio.TimeoutError("No login response received"),  # Login response timeout
        ]
        valve.packet_queue = mock_queue

        # Setup initial hello packet
        initial_hello = MagicMock(spec=HelloPacket)
        initial_hello.seed = 42
        initial_hello.authenticated = False

        # Mock packet parser
        mock_packet_parser.parse_packet.return_value = initial_hello

        # Mock login packet generation
        mock_login_packet = bytes([0x76] * 20)
        with patch("pycsmeter.valve._LoginPacket") as mock_login:
            mock_login.return_value.generate.return_value = mock_login_packet

            # Attempt connection - should fail but not raise exception
            result = await valve.connect("1234")
            assert result is False
            assert not valve.authenticated

            # Verify connection and packet sequence
            mock_bleak_client.connect.assert_called_once()
            mock_bleak_client.start_notify.assert_called_once()

            # Verify both hello and login packets were sent
            assert mock_bleak_client.write_gatt_char.call_count == 2
            hello_call = mock_bleak_client.write_gatt_char.call_args_list[0]
            login_call = mock_bleak_client.write_gatt_char.call_args_list[1]
            assert hello_call.args[1] == bytes([0x74] * 20)  # Hello packet
            assert login_call.args[1] == mock_login_packet  # Login packet

            # Verify queue operations
            assert mock_queue.get.await_count == 2

            # Verify packet parser was called once (only for initial hello)
            assert mock_packet_parser.parse_packet.call_count == 1

    @pytest.mark.asyncio
    async def test_get_data_empty_packet_sequence_fails(
        self, valve, mock_bleak_client, mock_packet_parser, mock_dashboard_packet, mock_advanced_packet
    ):
        """Test get_data when empty packet sequence fails (line 194)."""
        try:
            valve.connected = True
            valve.authenticated = True
            valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

            # Create an iterator for queue responses
            def queue_responses():
                # Will yield the same sequence for each attempt
                while True:
                    yield b"mock_packet"  # dashboard
                    yield b"mock_packet"  # advanced
                    yield b"mock_packet"  # empty1 - will fail

            # Create an iterator for parser responses
            def parser_responses():
                # Will yield the same sequence for each attempt
                while True:
                    yield mock_dashboard_packet
                    yield mock_advanced_packet
                    yield EOFError("Expected EmptyPacket #1")

            # Setup mocks with infinite iterators
            mock_queue = AsyncMock()
            mock_queue.get.side_effect = queue_responses()
            valve.packet_queue = mock_queue

            mock_packet_parser.parse_packet.side_effect = parser_responses()

            # Setup sleep mock and run test
            with patch("asyncio.sleep") as mock_sleep:
                # Should raise after 3 attempts
                with pytest.raises(DataRetrievalError, match="Failed to retrieve data from valve .* after 3 attempts"):
                    await valve.get_data()

                # Verify all three attempts were made
                assert mock_bleak_client.write_gatt_char.call_count == 3  # One data request per attempt

                # Verify each write was the correct data request packet
                for call in mock_bleak_client.write_gatt_char.call_args_list:
                    assert call.args[1] == bytes([0x75] * 20)  # Data request packet
                    assert call.kwargs["response"] is False

                # Verify queue operations - 3 packets per attempt * 3 attempts
                assert mock_queue.get.await_count == 9

                # Verify packet parser calls - 3 packets per attempt * 3 attempts
                assert mock_packet_parser.parse_packet.call_count == 9

                # Verify sleep was called between attempts
                assert mock_sleep.await_count == 2  # Called between attempts
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
    async def test_get_data_success_first_try(
        self,
        valve,
        mock_bleak_client,
        mock_packet_parser,
        mock_dashboard_packet,
        mock_advanced_packet,
        mock_history_packet,
    ):
        """Test successful get_data on first attempt (lines 194, 199)."""
        valve.connected = True
        valve.authenticated = True
        valve.uart[NORDIC_UART_WRITE] = mock_bleak_client.services[0].characteristics[1]

        # Create an iterator for queue responses - successful sequence
        def queue_responses():
            # Single successful attempt
            yield b"mock_packet"  # dashboard
            yield b"mock_packet"  # advanced
            yield b"mock_packet"  # empty1
            yield b"mock_packet"  # empty2
            yield b"mock_packet"  # empty3
            yield b"mock_packet"  # history

        # Create an iterator for parser responses - successful sequence
        def parser_responses():
            # Single successful attempt
            yield mock_dashboard_packet
            yield mock_advanced_packet
            yield EmptyPacket()
            yield EmptyPacket()
            yield EmptyPacket()
            yield mock_history_packet

        # Setup mocks
        mock_queue = AsyncMock()
        mock_queue.get.side_effect = queue_responses()
        valve.packet_queue = mock_queue

        mock_packet_parser.parse_packet.side_effect = parser_responses()

        # Should succeed on first try
        result = await valve.get_data()

        # Verify result is ValveData
        assert isinstance(result, ValveData)

        # Verify only one attempt was made
        assert mock_bleak_client.write_gatt_char.call_count == 1

        # Verify data request packet
        data_request = mock_bleak_client.write_gatt_char.call_args
        assert data_request.args[1] == bytes([0x75] * 20)  # Data request packet
        assert data_request.kwargs["response"] is False

        # Verify queue operations - 6 packets for successful attempt
        assert mock_queue.get.await_count == 6

        # Verify packet parser calls - 6 packets for successful attempt
        assert mock_packet_parser.parse_packet.call_count == 6
