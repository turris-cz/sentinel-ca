"""
PyTest init, mocks and fixtures
"""
import sys
sys.path.append("..")

from unittest.mock import Mock

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.ca import CA

from ..helpers import build_ca_config, build_checker_reply
from ..crypto_helpers import build_request


# Request fixtures -----------------------------------------
@pytest.fixture
def good_request():
    return build_request()


# Checker reply fixtures -----------------------------------
@pytest.fixture
def checker_good_reply():
    return build_checker_reply()


# CA fixtures ----------------------------------------------
@pytest.fixture
def ca(tmpdir):
    ca_config = build_ca_config(tmpdir)
    with db_connection(ca_config) as db:
        yield CA(ca_config, db)


# Mocks ----------------------------------------------------
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
def good_socket_mock(socket_mock, checker_good_reply):
    socket_mock.recv_multipart.return_value = checker_good_reply
    return socket_mock
