"""Tests for the CLI interface."""

import asyncio
from datetime import date
from unittest.mock import AsyncMock, patch
import warnings

import pytest
from click.testing import CliRunner

from pycsmeter.cli import main
from pycsmeter.exceptions import AuthenticationError, ValveConnectionError
from pycsmeter.valve import AdvancedData, DashboardData, HistoryItem, ValveData


@pytest.fixture(autouse=True)
def event_loop():
    """Create and set an event loop for each test."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def ignore_unraisable_warning():
    """Ignore PytestUnraisableExceptionWarning warnings."""
    warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)
    yield


@pytest.fixture
def mock_valve():
    """Create a mock Valve instance."""
    with patch("pycsmeter.cli.Valve") as mock:
        valve = AsyncMock()
        valve.connect = AsyncMock()
        valve.disconnect = AsyncMock()
        valve.get_data = AsyncMock()
        mock.return_value = valve
        yield valve


@pytest.fixture
def mock_valve_data():
    """Create mock valve data for testing."""
    dashboard = DashboardData(
        hour=14,
        minute=30,
        battery_voltage=3.3,
        current_flow=5.5,
        soft_water_remaining=1000,
        treated_usage_today=50,
        peak_flow_today=7.5,
        water_hardness=15,
        regeneration_hour=2,
    )

    advanced = AdvancedData(
        regeneration_days=7,
        days_to_regeneration=3,
    )

    history = [
        HistoryItem(item_date=date(2024, 1, 1), gallons_per_day=100.0),
        HistoryItem(item_date=date(2024, 1, 2), gallons_per_day=150.0),
    ]

    return ValveData(dashboard=dashboard, advanced=advanced, history=history)


def test_connect_success(mock_valve):
    """Test successful valve connection."""
    runner = CliRunner()
    mock_valve.connect.return_value = True

    result = runner.invoke(main, ["connect", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Successfully connected" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.disconnect.assert_awaited_once()


def test_connect_auth_failure(mock_valve):
    """Test failed valve authentication."""
    runner = CliRunner()
    mock_valve.connect.return_value = False

    result = runner.invoke(main, ["connect", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Failed to authenticate" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.disconnect.assert_awaited_once()


def test_connect_error(mock_valve):
    """Test connection error handling."""
    runner = CliRunner()
    mock_valve.connect.side_effect = ValveConnectionError("Connection failed")

    result = runner.invoke(main, ["connect", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Error connecting to valve" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.disconnect.assert_awaited_once()


def test_status_success(mock_valve, mock_valve_data):
    """Test successful valve status retrieval."""
    runner = CliRunner()
    mock_valve.connect.return_value = True
    mock_valve.get_data.return_value = mock_valve_data

    result = runner.invoke(main, ["status", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    # Verify all sections are present
    assert "=== Dashboard ===" in result.output
    assert "=== Advanced Settings ===" in result.output
    assert "=== Recent History ===" in result.output
    # Verify some key data points
    assert "14:30" in result.output  # Time
    assert "3.3V" in result.output  # Battery
    assert "5.5 GPM" in result.output  # Current Flow
    assert "regeneration days          7" in result.output.lower()  # Regeneration Days
    assert "2024-01-01" in result.output  # History date
    assert "100.0 gallons" in result.output  # History usage

    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.get_data.assert_awaited_once()
    mock_valve.disconnect.assert_awaited_once()


def test_status_auth_failure(mock_valve):
    """Test status command with authentication failure."""
    runner = CliRunner()
    mock_valve.connect.return_value = False

    result = runner.invoke(main, ["status", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Failed to authenticate" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.disconnect.assert_awaited_once()
    mock_valve.get_data.assert_not_awaited()


def test_status_connection_error(mock_valve):
    """Test status command with connection error."""
    runner = CliRunner()
    mock_valve.connect.side_effect = ValveConnectionError("Connection failed")

    result = runner.invoke(main, ["status", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Error connecting to valve" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.disconnect.assert_awaited_once()
    mock_valve.get_data.assert_not_awaited()


def test_status_data_error(mock_valve):
    """Test status command with data retrieval error."""
    runner = CliRunner()
    mock_valve.connect.return_value = True
    mock_valve.get_data.side_effect = AuthenticationError("Not authenticated")

    result = runner.invoke(main, ["status", "00:11:22:33:44:55", "1234"])

    assert result.exit_code == 0
    assert "Error getting valve data" in result.output
    mock_valve.connect.assert_awaited_once_with("1234")
    mock_valve.get_data.assert_awaited_once()
    mock_valve.disconnect.assert_awaited_once()


def test_cli_help():
    """Test CLI help output."""
    runner = CliRunner()

    # Test main help
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "CS water softener valves" in result.output

    # Test connect command help
    result = runner.invoke(main, ["connect", "--help"])
    assert result.exit_code == 0
    assert "Test connection to a valve" in result.output
    assert "ADDRESS" in result.output
    assert "PASSWORD" in result.output

    # Test status command help
    result = runner.invoke(main, ["status", "--help"])
    assert result.exit_code == 0
    assert "Get current status from a valve" in result.output
    assert "ADDRESS" in result.output
    assert "PASSWORD" in result.output


def test_cli_missing_arguments():
    """Test CLI with missing arguments."""
    runner = CliRunner()

    # Test connect with missing password
    result = runner.invoke(main, ["connect", "00:11:22:33:44:55"])
    assert result.exit_code == 2
    assert "Missing argument" in result.output

    # Test connect with missing address and password
    result = runner.invoke(main, ["connect"])
    assert result.exit_code == 2
    assert "Missing argument" in result.output

    # Test status with missing password
    result = runner.invoke(main, ["status", "00:11:22:33:44:55"])
    assert result.exit_code == 2
    assert "Missing argument" in result.output

    # Test status with missing address and password
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 2
    assert "Missing argument" in result.output
