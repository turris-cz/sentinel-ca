"""
Test whole CA processing a request
"""

import json

import sn
from sentinel_ca.main import process

from .crypto_helpers import build_good_request, cert_from_bytes, get_cert_common_name, csr_from_str


def dict_to_bytes(d):
    return bytes(json.dumps(d), encoding='utf-8')


def bytes_to_dict(b):
    return json.loads(str(b), encoding='utf-8')


def checker_good_reply():
    return sn.encode_msg(
            "sentinel/certificator/checker",
            {
                "status": "ok",
                "message": "",
            }
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
