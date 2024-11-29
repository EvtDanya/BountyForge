import pytest
from honeypot.config import settings, Config


@pytest.fixture(scope='session')
def test_settings() -> Config:
    return settings
