"""Shared test configuration and fixtures."""

import pytest


def pytest_configure(config):  # noqa: ARG001
    """Configure pytest."""
    pytest.register_assert_rewrite("tests.helpers")
