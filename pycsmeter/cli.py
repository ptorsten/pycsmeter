"""Command line interface for pycsmeter."""

import asyncio
from typing import Optional

import click
from tabulate import tabulate

from pycsmeter.valve import Valve, ValveData


def _format_valve_data(data: ValveData) -> str:
    """Format valve data into a human readable string."""
    output = []

    # Dashboard section
    output.append("\n=== Dashboard ===")
    dashboard_data = [
        ["Time", f"{data.dashboard.hour:02d}:{data.dashboard.minute:02d}"],
        ["Battery", f"{data.dashboard.battery_voltage:.1f}V"],
        ["Current Flow", f"{data.dashboard.current_flow:.1f} GPM"],
        ["Soft Water Remaining", f"{data.dashboard.soft_water_remaining} gallons"],
        ["Today's Usage", f"{data.dashboard.treated_usage_today} gallons"],
        ["Today's Peak Flow", f"{data.dashboard.peak_flow_today:.1f} GPM"],
        ["Water Hardness", f"{data.dashboard.water_hardness} grains"],
        ["Regeneration Hour", f"{data.dashboard.regeneration_hour:02d}:00"],
    ]
    output.append(tabulate(dashboard_data, tablefmt="simple"))

    # Advanced section
    output.append("\n=== Advanced Settings ===")
    advanced_data = [
        ["Regeneration Days", str(data.advanced.regeneration_days)],
        ["Days to Next Regeneration", str(data.advanced.days_to_regeneration)],
    ]
    output.append(tabulate(advanced_data, tablefmt="simple"))

    # History section
    output.append("\n=== Recent Water Usage History ===")
    water_usage_history_data = [
        [item.date.strftime("%Y-%m-%d"), f"{item.gallons_per_day:.1f} gallons"]
        for item in data.water_usage_history[:14]  # Show last 14 days
    ]
    output.append(tabulate(water_usage_history_data, headers=["Date", "Usage"], tablefmt="simple"))

    return "\n".join(output)


async def _connect_valve(address: str, password: str) -> Optional[Valve]:
    """Connect to a valve and return the connected instance if successful."""
    valve = Valve(address)
    try:
        success = await valve.connect(password)
        if not success:
            click.echo("Failed to authenticate with valve. Please check your password.", err=True)
            await valve.disconnect()
            return None
    except Exception as e:  # noqa: BLE001
        click.echo(f"Error connecting to valve: {e}", err=True)
        await valve.disconnect()
        return None

    return valve

@click.group()
def main() -> None:
    """Command line interface for interacting with CS water softener valves."""


@main.command()
@click.argument("address")
@click.argument("password")
def connect(address: str, password: str) -> None:
    """Test connection to a valve.

    Parameters:
        address: The Bluetooth address of the valve (e.g. 00:11:22:33:44:55)
        password: The valve's connection password
    """

    async def _run() -> None:
        valve = await _connect_valve(address, password)
        if valve:
            click.echo(f"Successfully connected to valve at {address}")
            await valve.disconnect()

    asyncio.run(_run())


@main.command()
@click.argument("address")
@click.argument("password")
def status(address: str, password: str) -> None:
    """Get current status from a valve.

    Parameters:
        address: The Bluetooth address of the valve (e.g. 00:11:22:33:44:55)
        password: The valve's connection password
    """

    async def _run() -> None:
        valve = await _connect_valve(address, password)
        if valve:
            try:
                # await valve.get_data2()
                data = await valve.get_data()
                click.echo(_format_valve_data(data))
            except Exception as e:  # noqa: BLE001
                click.echo(f"Error getting valve data: {e}", err=True)
            finally:
                await valve.disconnect()

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    main()
