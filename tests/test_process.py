"""
Test whole CA processing a request
"""

import json

import pytest

import sn
from sentinel_ca.main import process

from .crypto_helpers import \
        bad_request_empty, \
        bad_request_missing, \
        bad_request_invalid_csr, \
        bad_request_invalid_csr_name, \
        bad_request_invalid_csr_hash, \
        good_request, \
        cert_from_bytes, \
        csr_from_str, \
        get_cert_common_name
from .sn_helpers import \
        checker_bad_reply1, \
        checker_bad_reply2, \
        checker_error_reply, \
        checker_fail_reply, \
        checker_good_reply


def dict_to_bytes(d):
    return bytes(json.dumps(d), encoding='utf-8')


def bytes_to_dict(b):
    return json.loads(str(b), encoding='utf-8')


def test_process_good_request(redis_mock, socket_mock, ca):
    # prepare env
    req = good_request()
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_good_reply()

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert socket_mock.send_multipart.called
    assert socket_mock.send_multipart.call_count == 1
    msg = socket_mock.send_multipart.call_args[0][0]
    msg_type, msg_payload = sn.parse_msg(msg)
    assert msg_type == "sentinel/certificator/checker"
    for key in ("sn", "nonce", "digest", "auth_type"):
        assert key in msg_payload
        assert msg_payload[key] == req[key]

    # Check redis interaction
    assert redis_mock.set.called
    assert redis_mock.set.call_count == 2
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[1][0][1])
    assert auth_state["status"] == "ok"
    # cert
    cert_bytes = redis_mock.set.call_args_list[0][0][1]
    cert = cert_from_bytes(cert_bytes)
    assert get_cert_common_name(cert) == req["sn"]

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert ca.get_valid_cert_matching_csr(req["sn"], csr)


@pytest.mark.parametrize(
        "param",
        (
            {"req": bad_request_invalid_csr(), "has_csr": False},
            {"req": bad_request_invalid_csr_name(), "has_csr": True},
            {"req": bad_request_invalid_csr_hash(), "has_csr": True},
        )
)
def test_process_bad_request_invalid_csr(redis_mock, socket_mock, ca, param):
    # prepare env
    req = param["req"]
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_good_reply()

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert not socket_mock.send_multipart.called

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == "fail"

    # Check certs in sqlite
    if param["has_csr"]:
        csr = csr_from_str(req["csr_str"])
        assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_empty_redis(redis_mock, socket_mock, ca):
    # prepare env
    redis_mock.brpop.return_value = None
    socket_mock.recv_multipart.return_value = checker_good_reply()

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert not socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called


def test_process_bad_request_empty(redis_mock, socket_mock, ca):
    # prepare env
    req = bad_request_empty()
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_good_reply()

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert not socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called


@pytest.mark.parametrize("req", bad_request_missing())
def test_process_bad_request_missing(redis_mock, socket_mock, ca, req):
    # prepare env
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_good_reply()

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert not socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called

    if "csr_str" in req and "sn" in req:
        csr = csr_from_str(req["csr_str"])
        assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


@pytest.mark.parametrize(
        "param",
        (
            {"reply": checker_fail_reply(), "status": "fail"},
            {"reply": checker_error_reply(), "status": "error"},
            {"reply": checker_bad_reply1(), "status": "error"},
            {"reply": checker_bad_reply2(), "status": "error"},
        )
)
def test_process_bad_reply(redis_mock, socket_mock, ca, param):
    # prepare env
    req = good_request()
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = param["reply"]

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert socket_mock.send_multipart.call_count == 1

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == param["status"]

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert not ca.get_valid_cert_matching_csr(req["sn"], csr)
