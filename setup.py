from __future__ import annotations

from setuptools import setup, find_packages

setup(
    name="sorcino",
    version="0.1.0",
    description="LLM Proxy Misconfiguration Scanner",
    author="Renato Zero",
    license="MIT",
    packages=find_packages(),
    py_modules=["cli"],
    install_requires=[
        "aiohttp>=3.9.0",
        "aiodns>=3.0.0",
        "websockets>=12.0",
        "pyyaml>=6.0",
        "typer>=0.9.0",
        "rich>=13.0.0",
        "zeroconf>=0.131.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0"],
    },
    entry_points={
        "console_scripts": [
            "sorcino=cli:app",
        ],
    },
    package_data={
        "fingerprint": ["signatures/*.yaml"],
        "": ["config/*.yaml"],
    },
    python_requires=">=3.9",
)
