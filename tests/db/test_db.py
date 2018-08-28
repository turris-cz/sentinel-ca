"""
Test db stuff
"""

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.exceptions import CASetupError


def test_db_init(db_config):
    with pytest.raises(CASetupError):
        with db_connection(db_config) as db:
            pass
