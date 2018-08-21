"""
Test db stuff
"""

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.exceptions import CASetupError


def test_db_empty(db_config_empty):
    with pytest.raises(CASetupError):
        with db_connection(db_config_empty) as db:
            pass


def test_db_missing_column(db_config_missing_column):
    with pytest.raises(CASetupError):
        with db_connection(db_config_missing_column) as db:
            pass


def test_db_wrong_table_name(db_config_wrong_table_name):
    with pytest.raises(CASetupError):
        with db_connection(db_config_wrong_table_name) as db:
            pass
