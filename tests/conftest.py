"""
PyTest init, mocks and fixtures
"""
import sys
sys.path.append("..")

from unittest.mock import Mock

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.ca import CA

from .ca_helpers import build_ca_config
from .sn_helpers import checker_good_reply


@pytest.fixture
def redis_mock():
    redis_instance = Mock()
    redis_instance.set
    # every tests should define its return value
    redis_instance.brpop.return_value = None

    return redis_instance


@pytest.fixture
def socket_mock():
    socket = Mock()
    socket.send_multipart
    # every tests should define its return value
    socket.recv_multipart.return_value = None

    return socket


@pytest.fixture
def good_socket_mock(socket_mock):
    socket_mock.recv_multipart.return_value = checker_good_reply()
    return socket_mock


@pytest.fixture
def ca(tmpdir):
    ca_config = build_ca_config(tmpdir)
    with db_connection(ca_config) as db:
        yield CA(ca_config, db)


@pytest.fixture
def ca_expire_soon(tmpdir):
    ca_config = build_ca_config(tmpdir, expire_soon=True)
    with db_connection(ca_config) as db:
        yield CA(ca_config, db)
