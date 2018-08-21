"""
Test whole CA processing a request
"""

import json

import pytest

import sn
from sentinel_ca.main import process

from .crypto_helpers import build_good_request, cert_from_bytes, get_cert_common_name, csr_from_str


def dict_to_bytes(d):
    return bytes(json.dumps(d), encoding='utf-8')


def bytes_to_dict(b):
    return json.loads(str(b), encoding='utf-8')


def build_checker_reply(status="ok", message="", msg_type="sentinel/certificator/checker"):
    # add status and message to the payload if they are not None
    msg_payload = {}
    if status is not None:
        msg_payload["status"] = status
    if message is not None:
        msg_payload["message"] = message

    return sn.encode_msg(msg_type, msg_payload)


def checker_good_reply():
    return build_checker_reply()


def checker_fail_reply():
    return build_checker_reply("fail", "Auth error happened")


def checker_error_reply():
    return build_checker_reply("error", "Checker error")


def checker_bad_reply1():
    return build_checker_reply(None, "Interface malformed: Status is missing")


def checker_bad_reply2():
    return build_checker_reply(
            "ok",
            "Interface malformed: Wrong message type",
            "sentinel/certificator/foo"
    )


def test_process_good_request(redis_mock, socket_mock, ca):
    # prepare env
    req = build_good_request()
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
            {"reply": checker_fail_reply(), "status": "fail"},
            {"reply": checker_error_reply(), "status": "error"},
            {"reply": checker_bad_reply1(), "status": "error"},
            {"reply": checker_bad_reply2(), "status": "error"},
        )
)
def test_process_bad_reply(redis_mock, socket_mock, ca, param):
    # prepare env
    req = build_good_request()
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
