import json
import struct
import typing
from datetime import date, datetime, timedelta
from typing import Optional

from pycsmeter.exceptions import PacketParseError


class InvalidPacket:
    """Represents an invalid or unrecognized BLE packet."""

    def __init__(self):
        """Initialize an invalid packet."""

    def validate(self) -> None:
        """Validate the invalid packet (no-op)."""

    @staticmethod
    def from_bytes(data: Optional[bytes] = None) -> "InvalidPacket":  # noqa: ARG004
        """Create an InvalidPacket from bytes."""
        return InvalidPacket()

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of an invalid packet."""
        return json.dumps({}, indent=indent)

    def __repr__(self):
        """Return a string representation of the invalid packet."""
        return "<InvalidPacket>"

    def __eq__(self, other: object) -> bool:
        """Check equality with another InvalidPacket."""
        return isinstance(other, InvalidPacket)


class DashboardPacket:
    """Represents and parses a dashboard data packet."""

    def __init__(self, data: bytes):
        """Parse and initialize a DashboardPacket from raw bytes."""
        if len(data) < 18:
            raise ValueError("Dashboard packet too short")
        # hour, minute, hour_pm, battery_adc, current_flow(u16), soft_remaining(u16), treated_usage_today(u16), peak_flow_today(u16), water_hardness, regen_hour
        # hour_pm/pm is data[5], regen_hour pm is data[17]
        self.hour = data[3] + (12 if data[5] == 1 and data[3] < 12 else 0)
        self.minute = data[4]
        self.hour_pm = data[5]
        self.battery_adc = data[6]
        self.battery_volt = self.battery_adc * 0.08797
        self.current_flow = struct.unpack(">H", data[7:9])[0] / 100.0
        self.soft_remaining = struct.unpack(">H", data[9:11])[0]
        self.treated_usage_today = struct.unpack(">H", data[11:13])[0]
        self.peak_flow_today = struct.unpack(">H", data[13:15])[0] / 100.0
        self.water_hardness = data[15]
        self.regen_hour_raw = data[16]
        self.regen_hour_pm = data[17]
        self.regen_hour = self.regen_hour_raw + (12 if self.regen_hour_pm == 1 and self.regen_hour_raw < 12 else 0)
        self.raw = data

    def validate(self) -> None:
        """Validate the DashboardPacket fields."""
        if not (0 <= self.hour < 24):
            raise ValueError(f"hour out of range: {self.hour}")
        if not (0 <= self.minute < 60):
            raise ValueError(f"minute out of range: {self.minute}")
        if not (0 <= self.hour_pm <= 1):
            raise ValueError(f"hour_pm out of range: {self.hour_pm}")
        if not (0 <= self.battery_adc <= 255):
            raise ValueError(f"battery_adc out of range: {self.battery_adc}")
        if not (0 <= self.current_flow < 1000):
            raise ValueError(f"current_flow out of range: {self.current_flow}")
        if not (0 <= self.soft_remaining <= 65535):
            raise ValueError(f"soft_remaining out of range: {self.soft_remaining}")
        if not (0 <= self.treated_usage_today <= 65535):
            raise ValueError(
                f"treated_usage_today out of range: {self.treated_usage_today}",
            )
        if not (0 <= self.peak_flow_today < 1000):
            raise ValueError(f"peak_flow_today out of range: {self.peak_flow_today}")
        if not (0 <= self.water_hardness <= 255):
            raise ValueError(f"water_hardness out of range: {self.water_hardness}")
        if not (0 <= self.regen_hour < 24):
            raise ValueError(f"regen_hour out of range: {self.regen_hour}")
        if not (0 <= self.regen_hour_pm <= 1):
            raise ValueError(f"regen_hour_pm out of range: {self.regen_hour_pm}")

    @staticmethod
    def from_bytes(data: bytes) -> "DashboardPacket":
        """Create a validated DashboardPacket from bytes."""
        pkt = DashboardPacket(data)
        pkt.validate()
        return pkt

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the dashboard packet."""
        # All fields, including raw bytes
        return json.dumps(
            {
                "hour": self.hour,
                "minute": self.minute,
                "hour_pm": self.hour_pm,
                "battery_adc": self.battery_adc,
                "battery_volt": self.battery_volt,
                "current_flow": self.current_flow,
                "soft_remaining": self.soft_remaining,
                "treated_usage_today": self.treated_usage_today,
                "peak_flow_today": self.peak_flow_today,
                "water_hardness": self.water_hardness,
                "regen_hour": self.regen_hour,
                "regen_hour_raw": self.regen_hour_raw,
                "regen_hour_pm": self.regen_hour_pm,
            },
            indent=indent,
        )

    def __repr__(self):
        """Return string representation of the dashboard packet."""
        return (
            f"<DashboardPacket hour={self.hour} minute={self.minute} battery_volt={self.battery_volt:.2f} "
            f"current_flow={self.current_flow} soft_remaining={self.soft_remaining} "
            f"treated_usage_today={self.treated_usage_today} peak_flow_today={self.peak_flow_today} "
            f"water_hardness={self.water_hardness} regen_hour={self.regen_hour}>"
        )

    def __eq__(self, other: object) -> bool:
        """Check equality with another DashboardPacket."""
        if not isinstance(other, DashboardPacket):
            return False
        return self.__dict__ == other.__dict__


class AdvancedPacket:
    """Represents and parses an advanced status BLE packet."""

    def __init__(self, data: bytes):
        """Parse and initialize an AdvancedPacket from raw bytes."""
        # Rust: skip 3, then regen_days, days_to_regen
        if len(data) < 5:
            raise ValueError("Advanced packet too short")
        self.regen_days = data[3]
        self.days_to_regen = data[4]
        self.raw = data

    def validate(self) -> None:
        """Validate the AdvancedPacket fields."""
        if not (0 <= self.regen_days <= 255):
            raise ValueError(f"regen_days out of range: {self.regen_days}")
        if not (0 <= self.days_to_regen <= 255):
            raise ValueError(f"days_to_regen out of range: {self.days_to_regen}")

    @staticmethod
    def from_bytes(data: bytes) -> "AdvancedPacket":
        """Create a validated AdvancedPacket from bytes."""
        if len(data) < 5:
            raise ValueError("Advanced packet too short")
        pkt = AdvancedPacket(data)
        pkt.validate()
        return pkt

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the advanced packet."""
        return json.dumps(
            {
                "regen_days": self.regen_days,
                "days_to_regen": self.days_to_regen,
            },
            indent=indent,
        )

    def __repr__(self):
        """Return string representation of the advanced packet."""
        return f"<AdvancedPacket regen_days={self.regen_days} days_to_regen={self.days_to_regen}>"

    def __eq__(self, other: object) -> bool:
        """Check equality with another AdvancedPacket."""
        if not isinstance(other, AdvancedPacket):
            return False
        return self.regen_days == other.regen_days and self.days_to_regen == other.days_to_regen


class WaterUsageHistoryItem(typing.NamedTuple):
    date: date
    gallons_per_day: float

class WaterUsageHistoryPacket:
    """Represents a sequence of daily water usage history items from BLE."""

    def __init__(self, chunks: list[bytes]):
        """Initialize a WaterUsageHistoryPacket with raw packet chunks.

        Args:
            chunks: List of raw packet chunks to merge

        Raises:
            PacketParseError: If given raw chunks that cannot be merged into valid history data
        """
        if not chunks:
            raise PacketParseError("No water usage history chunks provided")

        # Process raw packet chunks
        self.history_data = self._merge_history_chunks(chunks)

        self.yesterday = datetime.now().date() - timedelta(days=1)  # noqa: DTZ005

    @staticmethod
    def _merge_history_chunks(chunks: list[bytes]) -> bytes:
        """Merge multiple water usage history packet chunks into a single byte array."""
        if not chunks:
            raise PacketParseError("No history chunks provided")

        if len(chunks) != 4:
            raise PacketParseError("Invalid number of history chunks")

        # First chunk should be 17 bytes after header
        if len(chunks[0]) < 19 or chunks[0][0:2] != b"\x75\x75" or chunks[0][2] != 2:
            raise PacketParseError("Invalid first water usage history chunk")

        history_data = list(chunks[0][3:20])  # Skip header bytes
        # Second chunk should be 20 bytes
        if len(chunks[1]) < 20:
            raise PacketParseError("Second history chunk too short")
        history_data.extend(chunks[1][0:20])

        # Third chunk should be 20 bytes
        if len(chunks[2]) < 20:
            raise PacketParseError("Third history chunk too short")
        history_data.extend(chunks[2][0:20])

        # Fourth chunk should be 5 bytes
        if len(chunks[3]) < 5:
            raise PacketParseError("Fourth history chunk too short")
        history_data.extend(chunks[3][0:5])

        return bytes(history_data)

    def validate(self) -> None:
        """Validate the water usage history data."""
        if len(self.history_data) != 62:
            raise ValueError(f"History data must be 62 bytes, got {len(self.history_data)}")

    def get_history_for_date(self, target_date: date) -> Optional[float]:
        """Return the gallons per day for a specific date, if available.

        Args:
            target_date: The date to get history for

        Returns:
            Gallons per day for the date if found, None if date not in history
        """
        # Calculate days ago from yesterday
        days_ago = (self.yesterday - target_date).days

        if 0 <= days_ago < 62:
            # Each history entry is 1 byte
            gallons = self.history_data[days_ago]
            return float(gallons) * 10.0
        return None

    def get_history_last_n_days(self, n: int) -> list[WaterUsageHistoryItem]:
        """Return the most recent n days of water usage history.

        Args:
            n: Number of days of history to return

        Returns:
            List of (date, gallons) tuples, most recent first
        """
        n = min(n, 62)  # Cap at 62 days

        result = []
        for i in range(n):
            entry_date = self.yesterday - timedelta(days=i)
            # Each history entry is 1 byte
            gallons = self.history_data[i]
            result.append(WaterUsageHistoryItem(date=entry_date, gallons_per_day=float(gallons) * 10.0))
        return result

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the water usage history data."""
        history = []

        for i in range(len(self.history_data)):  # Each entry is 1 byte
            entry_date = self.yesterday - timedelta(days=i)
            # Each history entry is 1 byte
            gallons = self.history_data[i]
            history.append({
                "date": entry_date.isoformat(),
                "gallons_per_day": float(gallons) * 10.0,
            })

        return json.dumps(history, indent=indent)

    def __repr__(self) -> str:
        """Return string representation of the water usage history packet."""
        return "<WaterUsageHistoryPacket 62 bytes>"


class HelloPacket:
    """Represents and parses a hello BLE packet."""

    def __init__(self, data: bytes):
        """Parse and initialize a HelloPacket from raw bytes."""
        if len(data) < 17:
            raise ValueError("Invalid hello packet length")
        self.seed = data[11]
        self.major_version = int(f"{data[5]:02X}")
        self.minor_version = int(f"{data[6]:02X}")
        self.version = self.major_version * 100 + self.minor_version
        self.serial = f"{data[13]:02X}{data[14]:02X}{data[15]:02X}{data[16]:02X}"
        self.authenticated = data[7] == 0x80
        self.raw = data

    def validate(self) -> None:
        """Validate the HelloPacket fields."""
        if not (0 <= self.seed <= 255):
            raise ValueError(f"seed out of range: {self.seed}")
        if not (0 <= self.major_version <= 255):
            raise ValueError(f"major_version out of range: {self.major_version}")
        if not (0 <= self.minor_version <= 255):
            raise ValueError(f"minor_version out of range: {self.minor_version}")
        if not isinstance(self.serial, str) or len(self.serial) != 8:
            raise ValueError(f"serial format invalid: {self.serial}")
        if not isinstance(self.authenticated, bool):
            raise TypeError("authenticated must be bool")

    @staticmethod
    def from_bytes(data: bytes) -> "HelloPacket":
        """Create a validated HelloPacket from bytes."""
        pkt = HelloPacket(data)
        pkt.validate()
        return pkt

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the hello packet."""
        return json.dumps(
            {
                "seed": self.seed,
                "major_version": self.major_version,
                "minor_version": self.minor_version,
                "version": self.version,
                "serial": self.serial,
                "authenticated": self.authenticated,
            },
            indent=indent,
        )

    def __repr__(self):
        """Return string representation of the hello packet."""
        return f"<HelloPacket seed={self.seed} version={self.version} serial={self.serial} authenticated={self.authenticated}>"

    def __eq__(self, other):  # noqa: ANN001
        """Check equality with another HelloPacket."""
        if not isinstance(other, HelloPacket):
            return False
        return (
            self.seed == other.seed
            and self.major_version == other.major_version
            and self.minor_version == other.minor_version
            and self.version == other.version
            and self.serial == other.serial
            and self.authenticated == other.authenticated
        )


class PasswordCrypto:
    """Implements bitwise password rotation algorithm."""

    def __init__(self):
        """Initialize the password crypto engine."""
        self.factor = 0
        self.idx = 0

    def init(self, number: int, factor: int) -> None:
        """Initialize crypto parameters."""
        self.idx = number & 0xFF
        self.factor = factor & 0xFF

    def rotate(self, index: int) -> int:
        """Perform bit rotation on an index."""
        byte_index = index & 0xFF
        byte_crypt = self.factor & 0xFF

        for _ in range(8):
            rotate = (byte_crypt & 0x80) != 0
            byte_crypt = (byte_crypt << 1) & 0xFF
            if byte_index & 0x80:
                byte_crypt |= 0x01
            byte_index = (byte_index << 1) & 0xFF
            if rotate:
                byte_crypt ^= self.idx & 0xFF

        self.factor = byte_crypt
        return byte_crypt


class LoginPacket:
    """Generates login packet bytes for authentication."""

    def __init__(self, seed: int, password: str):
        """Initialize a LoginPacket with seed and password."""
        self.seed = seed
        try:
            self.pin = int(password)
        except Exception as e:
            raise ValueError(f"Password must be convertible to int: {password}") from e

    def get_pin_to_array(self, number: int) -> list[int]:
        """Convert a PIN to digit buckets."""
        number = max(0, min(number, 9999))
        pos1 = number % 10
        pos2 = (number // 10) % 10
        pos3 = (number // 100) % 10
        pos4 = (number // 1000) % 10
        return [pos1, pos2, pos3, pos4]

    def generate(self) -> bytes:
        """Generate the login packet bytes."""
        crypt = PasswordCrypto()
        packet = [0x74] * 20
        psw_array = self.get_pin_to_array(self.pin)
        idx = 0x53
        random_byte1 = 0x0D
        random_byte2 = 0x99

        crypt.init(idx, random_byte1)
        seed = self.seed ^ crypt.rotate(random_byte2)
        packet[2] = 0x50
        packet[3] = 0x41
        packet[4] = idx
        packet[5] = random_byte1
        packet[6] = random_byte2

        packet[7] = crypt.rotate(seed) ^ psw_array[3]
        packet[8] = crypt.rotate(packet[7]) ^ psw_array[2]
        packet[9] = crypt.rotate(packet[8]) ^ psw_array[1]
        packet[10] = crypt.rotate(packet[9]) ^ psw_array[0]

        # Rest of packet not used, or at least not matter for auth
        return bytes(packet)


class PacketParser:
    """Parses raw BLE packets into packet objects."""

    def __init__(self):
        """Initialize the PacketParser."""

    async def parse(self, data: list[bytes]) -> object:
        """Parse a list of raw BLE packets into a structured object.

        Args:
            data: List of raw packet data to parse

        Returns:
            Parsed packet object

        Raises:
            PacketParseError: If a packet cannot be parsed
        """
        if len(data) == 0:
            raise PacketParseError("No data provided")

        # Hello packet
        if data[0][0] == 0x74 and data[0][1] == 0x74 and data[0][2] == 0:
            if len(data) != 1:
                raise PacketParseError("Expected only one data chunk for hello packet")

            hellopkt = HelloPacket(data[0])
            hellopkt.validate()
            return hellopkt

        # Dashboard or advanced or history packets
        if data[0][0] == 0x75 and data[0][1] == 0x75:
            if data[0][2] == 0:
                if len(data) != 1:
                    raise PacketParseError("Expected only one data chunk for hello packet")

                dashboardpkt = DashboardPacket(data[0])
                dashboardpkt.validate()
                return dashboardpkt

            if data[0][2] == 1:
                if len(data) != 1:
                    raise PacketParseError("Expected only one data chunk for hello packet")

                advancedpkt = AdvancedPacket(data[0])
                advancedpkt.validate()
                return advancedpkt

            if data[0][2] == 2:
                if len(data) != 4:
                    raise PacketParseError("Expected four data chunks for history packet")

                history_packet = WaterUsageHistoryPacket(data)
                history_packet.validate()
                return history_packet

        # Unknown packet
        raise PacketParseError(f"Unknown packet type: {data[0]!r}")


class ValveData:
    """Aggregates Dashboard, Advanced, and History packet data."""

    def __init__(self, dashboard: DashboardPacket, advanced: AdvancedPacket, history: WaterUsageHistoryPacket):
        """Initialize ValveData with dashboard, advanced, and history."""
        self.dashboard = dashboard
        self.advanced = advanced
        self.water_usage_history = history

    def get_history(self) -> list[WaterUsageHistoryItem]:
        """Return the list of WaterUsageHistoryItem objects, newest first."""
        return self.water_usage_history.get_history_last_n_days(62)  # Get all 62 days

    def get_history_for_date(self, target_date: date) -> Optional[float]:
        """Return the gallons per day for a specific date, if available."""
        return self.water_usage_history.get_history_for_date(target_date)

    def get_history_last_n_days(self, n: int) -> list[WaterUsageHistoryItem]:
        """Return the most recent n WaterUsageHistoryItem entries."""
        return self.water_usage_history.get_history_last_n_days(n)

    def validate(self) -> None:
        """Validate all contained packets."""
        self.dashboard.validate()
        self.advanced.validate()
        self.water_usage_history.validate()

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of all valve data."""
        water_usage_history_items = self.get_history()
        water_usage_history_json = [
            {
                "date": item.date.isoformat(),
                "gallons_per_day": item.gallons_per_day,
            }
            for item in water_usage_history_items
        ]

        data = {
            "dashboard": json.loads(self.dashboard.to_json()),
            "advanced": json.loads(self.advanced.to_json()),
            "water_usage_history": water_usage_history_json,
        }
        return json.dumps(data, indent=indent)

    def __repr__(self):
        """Return string representation of the ValveData."""
        history_items = self.get_history()
        return (
            f"<ValveData dashboard={self.dashboard!r} advanced={self.advanced!r} "
            f"history_items={len(history_items)}>"
        )
