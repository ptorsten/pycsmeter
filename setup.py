"""Setup configuration for pycsmeter package."""

from setuptools import find_packages, setup

setup(
    name="pycsmeter",
    version="0.1.0",
    description="Python client for CS water softener valves",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "bleak>=0.21.1,<0.22.0",  # Pin to last known working version
        "click>=8.1.0",
        "tabulate>=0.9.0",
    ],
    extras_require={
        "macos": ["pyobjc-core>=9.2,<10.0", "pyobjc-framework-CoreBluetooth>=9.2,<10.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pycsmeter=pycsmeter.cli:main",
        ],
    },
    python_requires=">=3.9",
)
