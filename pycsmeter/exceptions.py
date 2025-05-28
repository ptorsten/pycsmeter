"""Exceptions for pycsmeter."""

class ValveError(Exception):
    """Base exception for valve-related errors."""


class PacketError(ValveError):
    """Raised for packet parsing or validation errors."""


class PacketParseError(PacketError):
    """Raised when a raw packet cannot be parsed."""


class PacketValidationError(PacketError):
    """Raised when a parsed packet fails validation."""


class ValveConnectionError(ValveError):
    """Raised when BLE connection fails."""


class AuthenticationError(ValveError):
    """Raised when authentication to the valve fails."""


class DataRetrievalError(ValveError):
    """Raised when failing to retrieve data from the valve."""
