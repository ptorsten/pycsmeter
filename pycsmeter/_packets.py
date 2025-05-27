import json
import struct
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from pycsmeter.exceptions import PacketParseError


class EmptyPacket:
    """Represents an empty packet placeholder."""

    def __init__(self):
        """Initialize an empty packet."""

    def validate(self) -> None:
        """Validate the empty packet (no-op)."""
        # Nothing to validate, always valid

    @staticmethod
    def from_bytes(data: Optional[bytes] = None) -> "EmptyPacket":  # noqa: ARG004
        """Create an EmptyPacket from bytes."""
        # Accepts None or any bytes, just returns empty
        return EmptyPacket()

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of an empty packet."""
        return json.dumps({}, indent=indent)

    def __repr__(self):
        """Return a string representation of the empty packet."""
        return "<ValveEmptyPacket>"

    def __eq__(self, other: object) -> bool:
        """Check equality with another EmptyPacket."""
        return isinstance(other, EmptyPacket)


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
        # battery adc is data[6]
        self.battery_adc = data[6]
        self.battery_volt = self.battery_adc * 0.08797
        self.current_flow = struct.unpack(">H", data[7:9])[0] / 100.0
        self.soft_remaining = struct.unpack(">H", data[9:11])[0]
        self.treated_usage_today = struct.unpack(">H", data[11:13])[0]
        self.peak_flow_today = struct.unpack(">H", data[13:15])[0] / 100.0
        self.water_hardness = data[15]
        # regen_hour is data[16], pm flag is data[17]
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


@dataclass
class HistoryItem:
    """A dataclass representing a single day's history entry."""

    item_date: date  # Should be a datetime.date object
    gallon_per_day: float

    def validate(self) -> None:
        """Validate the HistoryItem fields."""
        if not isinstance(self.gallon_per_day, (int, float)):
            raise TypeError("gallon_per_day must be numeric")
        if not (0.0 <= self.gallon_per_day <= 2550.0):
            raise TypeError(f"gallon_per_day out of range: {self.gallon_per_day}")
        # date should be a datetime.date
        if not hasattr(self.item_date, "isoformat"):
            raise ValueError("date must be a date object")

    @staticmethod
    def from_bytes(item_date: date, byte_val: int) -> "HistoryItem":
        """Create a HistoryItem from raw bytes and date."""
        # byte_val is a single int/byte
        gallon_per_day = float(byte_val) * 10.0
        item = HistoryItem(item_date=item_date, gallon_per_day=gallon_per_day)
        item.validate()
        return item

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the history item."""
        # date is a datetime.date
        d = {"item_date": self.item_date.isoformat(), "gallon_per_day": self.gallon_per_day}
        return json.dumps(d, indent=indent)

    def __eq__(self, other: object) -> bool:
        """Check equality with another HistoryItem."""
        if not isinstance(other, HistoryItem):
            return False
        return self.item_date == other.item_date and self.gallon_per_day == other.gallon_per_day


class HistoryPacket:
    """Represents a sequence of daily history items from BLE."""

    def __init__(self, items: list[HistoryItem]):
        """Initialize a HistoryPacket with a list of HistoryItems."""
        if len(items) != 62:
            raise ValueError(f"HistoryPacket expects 62 items, got {len(items)}")
        self.history_gallons_per_day = items

    def validate(self) -> None:
        """Validate the HistoryPacket items."""
        if len(self.history_gallons_per_day) != 62:
            raise ValueError(
                f"HistoryPacket expects 62 items, got {len(self.history_gallons_per_day)}",
            )
        for item in self.history_gallons_per_day:
            item.validate()

    @staticmethod
    def from_bytes(data: bytes, start_date: date) -> "HistoryPacket":
        """Create a validated HistoryPacket from raw bytes and start date."""
        # data: 62 bytes, start_date: datetime.date
        if len(data) != 62:
            raise ValueError("History data must be 62 bytes")
        from datetime import timedelta

        items = []
        current_date = start_date
        for val in reversed(data):
            items.append(HistoryItem.from_bytes(current_date, val))
            current_date -= timedelta(days=1)
        pkt = HistoryPacket(items)
        pkt.validate()
        return pkt

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of the history packet."""
        arr = [item.to_json() for item in self.history_gallons_per_day]
        return json.dumps(arr, indent=indent)

    def __repr__(self) -> str:
        """Return string representation of the history packet."""
        return f"<HistoryPacket {len(self.history_gallons_per_day)} items>"

    def __eq__(self, other: object) -> bool:
        """Check equality with another HistoryPacket."""
        if not isinstance(other, HistoryPacket):
            return False
        return self.history_gallons_per_day == other.history_gallons_per_day


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
        # Buffer for history data packets
        self.history_data = []

    async def parse_packet(self, data: bytes) -> object:
        """Parse a raw BLE packet into a structured object."""
        # Handle ongoing history data buffering
        if self.history_data:
            # If we have already buffered first chunk (len 17)
            if len(self.history_data) == 17:
                if len(data) == 6:
                    # Unexpected end, reset
                    self.history_data = []
                    return InvalidPacket()
                # Buffer second chunk (20 bytes)
                self.history_data += list(data[0:20])
                # Now length should be 37
                # Return empty packet to indicate waiting for more
                return EmptyPacket()

            if len(self.history_data) == 37:
                if len(data) == 6:
                    # Unexpected end, reset
                    self.history_data = []
                    return InvalidPacket()
                # Buffer third chunk (20 bytes)
                self.history_data += list(data[0:20])
                # Now length should be 57
                # Return empty packet to indicate waiting for more
                return EmptyPacket()

            if len(self.history_data) == 57:
                self.history_data += list(data[0:5])
                # Now length should be 62
                # Build history items: 62 days, most recent first (reverse order)
                items = []

                # Start from yesterday
                current_date = datetime.now(timezone.utc).date() - timedelta(days=1)
                for val in reversed(self.history_data):
                    item = HistoryItem.from_bytes(current_date, val)
                    items.append(item)
                    current_date -= timedelta(days=1)
                # Reset buffer
                self.history_data = []
                # Return packet
                historypkt = HistoryPacket(items)
                historypkt.validate()
                return historypkt
            # If for some reason it's not the expected length, return empty
            self.history_data = []
            return InvalidPacket()

        # Hello packet
        if data[0] == 0x74 and data[1] == 0x74 and data[2] == 0:
            hellopkt = HelloPacket(data)
            hellopkt.validate()
            return hellopkt

        # Dashboard or advanced or history packets
        if data[0] == 0x75 and data[1] == 0x75:
            if data[2] == 0:
                dashboardpkt = DashboardPacket(data)
                dashboardpkt.validate()
                return dashboardpkt

            if data[2] == 1:
                advancedpkt = AdvancedPacket(data)
                advancedpkt.validate()
                return advancedpkt

            if data[2] == 2 and not self.history_data:
                # Buffer first chunk (data[2:19], 17 bytes)
                self.history_data = list(data[2:19])
                return EmptyPacket()

        # Unknown packet
        raise PacketParseError(f"Unknown packet type: {data!r}")


class ValveData:
    """Aggregates Dashboard, Advanced, and History packet data."""

    def __init__(self, dashboard: DashboardPacket, advanced: AdvancedPacket, history: HistoryPacket):
        """Initialize ValveData with dashboard, advanced, and history."""
        self.dashboard = dashboard
        self.advanced = advanced
        self.history = history

    def get_history(self) -> list[HistoryItem]:
        """Return the list of HistoryItem objects, newest first."""
        return self.history.history_gallons_per_day

    def get_history_for_date(self, date_obj: object) -> Optional[HistoryItem]:
        """Return the HistoryItem for the given date, or None if not found.

        date_obj should be a datetime.date.
        """
        for item in self.history.history_gallons_per_day:
            if item.item_date == date_obj:
                return item
        return None

    def get_history_last_n_days(self, n: int) -> list[HistoryItem]:
        """Return the most recent n HistoryItem entries."""
        return self.history.history_gallons_per_day[:n]

    def validate(self) -> None:
        """Validate all contained packets."""
        self.dashboard.validate()
        self.advanced.validate()
        self.history.validate()

    def to_json(self, indent: Optional[int] = None) -> str:
        """Return JSON representation of all valve data."""
        data = {
            "dashboard": json.loads(self.dashboard.to_json()),
            "advanced": json.loads(self.advanced.to_json()),
            "history": json.loads(self.history.to_json()),
        }
        return json.dumps(data, indent=indent)

    def __repr__(self):
        """Return string representation of the ValveData."""
        return (
            f"<ValveData dashboard={self.dashboard!r} advanced={self.advanced!r} "
            f"history_items={len(self.history.history_gallons_per_day)}>"
        )
