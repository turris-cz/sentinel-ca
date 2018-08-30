"""
PyTest init, mocks and fixtures
"""

import pytest

from ...crypto_helpers import build_request


# Request fixtures -----------------------------------------
@pytest.fixture
def good_request_renew():
    return build_request(renew=True)
