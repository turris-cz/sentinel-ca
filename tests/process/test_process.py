"""
Test CA processing a good request
"""

import sn
from sentinel_ca.main import process

from ..helpers import dict_to_bytes, bytes_to_dict
from ..crypto_helpers import cert_from_bytes, csr_from_str, get_cert_common_name


def test_process_good_request(redis_mock, good_socket_mock, ca, good_request):
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert good_socket_mock.send_multipart.call_count == 1
    msg = good_socket_mock.send_multipart.call_args[0][0]
    msg_type, msg_payload = sn.parse_msg(msg)
    assert msg_type == "sentinel/certificator/checker"
    for key in ("sn", "nonce", "signature", "auth_type"):
        assert key in msg_payload
        assert msg_payload[key] == req[key]

    # Check redis interaction
    assert redis_mock.set.call_count == 2
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[1][0][1])
    auth_state_ex = redis_mock.set.call_args_list[1][1]["ex"]
    assert auth_state["status"] == "ok"
    assert auth_state_ex > 0
    # cert
    cert_bytes = redis_mock.set.call_args_list[0][0][1]
    cert_bytes_ex = redis_mock.set.call_args_list[0][1]["ex"]
    cert = cert_from_bytes(cert_bytes)
    assert get_cert_common_name(cert) == req["sn"]
    assert cert_bytes_ex > 0

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert ca.get_valid_cert_matching_csr(req["sn"], csr)
