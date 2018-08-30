"""
PyTest init, mocks and fixtures
"""

import itertools

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.ca import CA

from ...helpers import build_ca_config, build_checker_reply
from ...crypto_helpers import build_request


# Request fixtures -----------------------------------------
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


def bad_request_missing_generator():
    req = build_request()
    for subreq in itertools.combinations(req, len(req)-1):
        yield {i: req[i] for i in subreq}


@pytest.fixture(params=bad_request_missing_generator())
def bad_request_missing(request):
    return request.param


@pytest.fixture(params=[
        build_request(valid_subject_name=False),
        build_request(valid_hash=False),
])
def bad_request_invalid_csr_params(request):
    return request.param


# Checker reply fixtures -----------------------------------
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
def ca_expire_soon(tmpdir):
    ca_config = build_ca_config(tmpdir, expire_soon=True)
    with db_connection(ca_config) as db:
        yield CA(ca_config, db)
