import asyncio
import uuid
from dataclasses import dataclass
from datetime import date
from typing import Optional

from bleak import BleakClient

from pycsmeter._packets import (
    AdvancedPacket as _AdvancedPacket,
)
from pycsmeter._packets import (
    DashboardPacket as _DashboardPacket,
)
from pycsmeter._packets import (
    EmptyPacket as _EmptyPacket,
)
from pycsmeter._packets import (
    HelloPacket as _HelloPacket,
)
from pycsmeter._packets import (
    HistoryPacket as _HistoryPacket,
)
from pycsmeter._packets import (
    LoginPacket as _LoginPacket,
)
from pycsmeter._packets import (
    PacketParser as _PacketParser,
)
from pycsmeter.exceptions import (
    AuthenticationError,
    DataRetrievalError,
    PacketValidationError,
    ValveConnectionError,
)

NORDIC_UART_READ = uuid.UUID("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
NORDIC_UART_WRITE = uuid.UUID("6e400002-b5a3-f393-e0a9-e50e24dcca9e")


@dataclass
class HistoryItem:
    """A single day's water usage history."""

    item_date: date
    gallons_per_day: float


@dataclass
class DashboardData:
    """Current valve dashboard status."""

    hour: int
    minute: int
    battery_voltage: float
    current_flow: float
    soft_water_remaining: int
    treated_usage_today: int
    peak_flow_today: float
    water_hardness: int
    regeneration_hour: int


@dataclass
class AdvancedData:
    """Advanced valve status information."""

    regeneration_days: int
    days_to_regeneration: int


@dataclass
class ValveData:
    """Complete valve status including dashboard, advanced, and history data."""

    dashboard: DashboardData
    advanced: AdvancedData
    history: list[HistoryItem]

    @classmethod
    def from_internal(
        cls,
        dashboard: _DashboardPacket,
        advanced: _AdvancedPacket,
        history: _HistoryPacket,
    ) -> "ValveData":
        """Create ValveData from internal packet types."""
        dashboard_data = DashboardData(
            hour=dashboard.hour,
            minute=dashboard.minute,
            battery_voltage=dashboard.battery_volt,
            current_flow=dashboard.current_flow,
            soft_water_remaining=dashboard.soft_remaining,
            treated_usage_today=dashboard.treated_usage_today,
            peak_flow_today=dashboard.peak_flow_today,
            water_hardness=dashboard.water_hardness,
            regeneration_hour=dashboard.regen_hour,
        )

        advanced_data = AdvancedData(
            regeneration_days=advanced.regen_days,
            days_to_regeneration=advanced.days_to_regen,
        )

        history_items = [
            HistoryItem(item_date=item.item_date, gallons_per_day=item.gallon_per_day)
            for item in history.history_gallons_per_day
        ]

        return cls(
            dashboard=dashboard_data,
            advanced=advanced_data,
            history=history_items,
        )

    def get_history_for_date(self, target_date: date) -> Optional[HistoryItem]:
        """Return the history item for a specific date, if available."""
        for item in self.history:
            if item.item_date == target_date:
                return item
        return None

    def get_history_last_n_days(self, n: int) -> list[HistoryItem]:
        """Return the most recent n days of history."""
        return self.history[:n]


class Valve:
    """Valve client for interacting with CS valves."""

    def __init__(self, address: str):
        """Initialize the Valve client with the given BLE device address."""
        self.address = address
        self.client = BleakClient(address)
        self.uart = {} # type: ignore  # noqa: PGH003
        self.packet_queue = asyncio.Queue() # type: ignore  # noqa: PGH003
        self.connected = False
        self.authenticated = False
        self.parser = _PacketParser()

    async def id(self) -> str:
        """Return a string identifier for this valve device (its BLE address)."""
        return str(self.address)

    async def connect(self, password: str) -> bool:
        """Connect to the valve via BLE, send authentication using the provided password, and return True if authentication succeeds."""
        if self.connected:
            raise ValveConnectionError(f"Valve {self.address} is already connected")

        # Connect BLE and send hello packet
        await self.__connect_to_valve()
        try:
            seed = self.hello_packet.seed
            login_packet = _LoginPacket(seed, password).generate()
            await self.__send_login(login_packet)

            packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
            parsed_packet = await self.parser.parse_packet(packet)
            if not isinstance(parsed_packet, _HelloPacket):
                raise PacketValidationError(f"Expected HelloPacket but received {type(parsed_packet).__name__}")

            if isinstance(parsed_packet, _HelloPacket) and parsed_packet.authenticated:
                self.authenticated = True
                return True
        except asyncio.TimeoutError:
            return False
        return False

    async def disconnect(self) -> None:
        """Disconnect from the valve if currently connected."""
        if self.connected:
            await self.client.disconnect()
            self.connected = False
            self.authenticated = False

    async def get_data(self) -> ValveData:
        """Retrieve Dashboard, Advanced, and History packets from the valve, returning a ValveData object. Retries up to three times on failure."""
        if not self.connected:
            raise ValveConnectionError(f"Not connected to valve {self.address}. Call connect() first")
        if not self.authenticated:
            raise AuthenticationError(
                f"Not authenticated with valve {self.address}. Authentication failed during connect()",
            )

        for attempt in range(3):
            try:
                return await self.__get_data()
            except EOFError:
                if attempt < 2:  # Only sleep if we're going to retry
                    await asyncio.sleep(0.1)

        raise DataRetrievalError(f"Failed to retrieve data from valve {self.address} after 3 attempts")

    async def __get_data(self) -> ValveData:
        try:
            await self.__send_get_data()
            packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
            dashboard_packet = await self.parser.parse_packet(packet)
            if not isinstance(dashboard_packet, _DashboardPacket):
                raise PacketValidationError(f"Expected DashboardPacket but received {type(dashboard_packet).__name__}")

            packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
            advanced_packet = await self.parser.parse_packet(packet)
            if not isinstance(advanced_packet, _AdvancedPacket):
                raise PacketValidationError(f"Expected AdvancedPacket but received {type(advanced_packet).__name__}")

            # BT isn't always reliable, and history requires four packets, so this can fail, then retry
            for empty_packet_num in range(3):
                packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
                empty_packet = await self.parser.parse_packet(packet)
                if not isinstance(empty_packet, _EmptyPacket):
                    raise EOFError(  # noqa: TRY004
                        f"Expected EmptyPacket #{empty_packet_num + 1} but received {type(empty_packet).__name__}",
                    )

            packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
            history_packet = await self.parser.parse_packet(packet)
            if not isinstance(history_packet, _HistoryPacket):
                raise PacketValidationError(f"Expected HistoryPacket but received {type(history_packet).__name__}")

            return ValveData.from_internal(dashboard_packet, advanced_packet, history_packet)
        except asyncio.TimeoutError as err:
            raise DataRetrievalError(
                f"Timeout while waiting for packets from valve {self.address} (15s timeout exceeded)",
            ) from err

    async def __connect_to_valve(self) -> None:
        if not self.connected:
            await self.client.connect()
            self.connected = True

        notify_char = None
        write_char = None
        for service in self.client.services:
            for char in service.characteristics:
                if char.uuid == str(NORDIC_UART_READ):
                    notify_char = char
                if char.uuid == str(NORDIC_UART_WRITE):
                    write_char = char

        if notify_char is None or write_char is None:
            missing = []
            if notify_char is None:
                missing.append("notify (read)")
            if write_char is None:
                missing.append("write")
            raise ValveConnectionError(
                f"Required UART characteristics not found on valve {self.address}: {', '.join(missing)}",
            )

        self.uart[NORDIC_UART_READ] = notify_char
        self.uart[NORDIC_UART_WRITE] = write_char

        await self.client.start_notify(notify_char, self._notification_handler)

        # Send hello packet to initiate communication
        await self.__send_hello()

        try:
            packet = await asyncio.wait_for(self.packet_queue.get(), timeout=15.0)
            parsed_packet = await self.parser.parse_packet(packet)
            if not isinstance(parsed_packet, _HelloPacket):
                raise PacketValidationError(f"Expected initial HelloPacket but received {type(parsed_packet).__name__}")
            self.hello_packet = parsed_packet
        except asyncio.TimeoutError as err:
            raise DataRetrievalError(
                f"Timeout while waiting for initial hello packet from valve {self.address} (15s timeout exceeded)",
            ) from err

    async def __send_hello(self) -> None:
        packet = bytes([0x74] * 20)
        await self.client.write_gatt_char(
            self.uart[NORDIC_UART_WRITE],
            packet,
            response=False,
        )

    async def __send_login(self, packet: bytes) -> None:
        await self.client.write_gatt_char(
            self.uart[NORDIC_UART_WRITE],
            packet,
            response=False,
        )

    async def __send_get_data(self) -> None:
        packet = bytes([0x75] * 20)
        await self.client.write_gatt_char(
            self.uart[NORDIC_UART_WRITE],
            packet,
            response=False,
        )

    def _notification_handler(self, sender, data: bytearray) -> None:  # noqa: ANN001, ARG002
        self.packet_queue.put_nowait(data)
