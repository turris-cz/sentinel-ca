"""
Test whole CA processing a repeated requests
"""

from sentinel_ca.main import process

from ...helpers import dict_to_bytes, bytes_to_dict
from ...crypto_helpers import cert_from_bytes, csr_from_str, get_cert_common_name


def test_process_repeated_request(redis_mock, good_socket_mock, ca, good_request):
    """Test repeated request (without renew flag) will not issue another
    certificate and the original one is served again
    """
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # issue the cert
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert good_socket_mock.send_multipart.called

    # Check redis interaction
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

    # test again with the same request
    process(redis_mock, good_socket_mock, ca)

    # Check redis interaction
    assert redis_mock.set.call_count == 4
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[3][0][1])
    assert auth_state["status"] == "ok"

    # second certificate match the first one
    second_cert_bytes = redis_mock.set.call_args_list[2][0][1]
    assert second_cert_bytes == cert_bytes


def test_process_renew(redis_mock, good_socket_mock, ca, good_request_renew):
    """Test repeated request with a renew flag will force the CA to issue
    and serve a new certificate
    """
    # prepare env
    req = good_request_renew
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # issue the cert
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert good_socket_mock.send_multipart.called

    # Check redis interaction
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

    # test again with the same request (with "renew" flag)
    process(redis_mock, good_socket_mock, ca)

    # Check redis interaction
    assert redis_mock.set.call_count == 4
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[3][0][1])
    assert auth_state["status"] == "ok"

    # second certificate does not match the first one
    second_cert_bytes = redis_mock.set.call_args_list[2][0][1]
    assert second_cert_bytes != cert_bytes
