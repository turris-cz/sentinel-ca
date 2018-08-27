"""
PyTest init, mocks and fixtures
"""
import sys
sys.path.append("..")

import itertools
from unittest.mock import Mock

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.ca import CA

from .ca_helpers import build_ca_config
from .crypto_helpers import build_request
from .sn_helpers import build_checker_reply


# Request fixtures -----------------------------------------
@pytest.fixture
def good_request():
    return build_request()


@pytest.fixture
def good_request_renew():
    return build_request(renew=True)


@pytest.fixture
def bad_request_empty():
    return None


@pytest.fixture
def bad_request_no_json():
    return "This is not a dictionary"


@pytest.fixture
def bad_request_invalid_csr():
    req = build_request()
    req["csr_str"] = "foobar"
    return req


@pytest.fixture(params=[
        build_request(valid_subject_name=False),
        build_request(valid_hash=False),
])
def bad_request_invalid_csr_params(request):
    return request.param


def bad_request_missing_generator():
    req = build_request()
    for subreq in itertools.combinations(req, len(req)-1):
        yield {i: req[i] for i in subreq}


@pytest.fixture(params=bad_request_missing_generator())
def bad_request_missing(request):
    return request.param


# Checker reply fixtures -----------------------------------
@pytest.fixture
def checker_good_reply():
    return build_checker_reply()


@pytest.fixture
def checker_fail_reply():
    return build_checker_reply(
            status="fail",
            message="Auth error happened"
    )


@pytest.fixture(params=[
        build_checker_reply(
                status="error",
                message="Checker error"
        ),
        build_checker_reply(
                status=None,
                message="Interface malformed: Status is missing"
        ),
        build_checker_reply(
                status="ok",
                message="Interface malformed: Wrong message type",
                msg_type="sentinel/certificator/foo"
        ),
])
def checker_error_reply(request):
    return request.param


# CA fixtures ----------------------------------------------
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
