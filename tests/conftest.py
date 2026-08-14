"""
Pytest conftest setup. Provides reusable fixtures for loading sample .eml files from tests/fixtures/.
"""

import pytest  # type: ignore # pyrefly: ignore [missing-import]
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def load_fixture(fixtures_dir):
    def _loader(filename: str) -> bytes:
        file_path = fixtures_dir / filename
        if not file_path.exists():
            pytest.fail(f"Fixture file not found: {file_path}")
        return file_path.read_bytes()
    return _loader
