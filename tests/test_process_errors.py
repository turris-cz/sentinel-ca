"""
Test CA raction to errors end bad requests
"""

import itertools
import json

import pytest

from sentinel_ca.main import process
from sentinel_ca.exceptions import CAError

from .helpers import dict_to_bytes, bytes_to_dict
from .crypto_helpers import build_request, csr_from_str


def test_process_cacert_expire_soon(redis_mock, good_socket_mock, ca_expire_soon, good_request):
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    with pytest.raises(CAError):
        process(redis_mock, good_socket_mock, ca_expire_soon)

    # Check SN interaction
    assert good_socket_mock.send_multipart.called

    # Check redis interaction
    assert not redis_mock.set.called

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert not ca_expire_soon.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_bad_request_invalid_csr(redis_mock, good_socket_mock, ca, bad_request_invalid_csr):
    # prepare env
    req = bad_request_invalid_csr
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == "fail"


def test_process_bad_request_invalid_csr_params(redis_mock, good_socket_mock, ca, bad_request_invalid_csr_params):
    # prepare env
    req = bad_request_invalid_csr_params
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == "fail"

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_empty_redis(redis_mock, good_socket_mock, ca):
    # prepare env
    redis_mock.brpop.return_value = None

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called


def test_process_bad_request_empty(redis_mock, good_socket_mock, ca, bad_request_empty):
    # prepare env
    req = bad_request_empty
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called


def test_process_bad_request_no_json(redis_mock, good_socket_mock, ca, bad_request_no_json):
    # prepare env
    req = bad_request_no_json
    redis_mock.brpop.return_value = (1, bytes(req, encoding='utf-8'))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called


def test_process_bad_request_encoding(redis_mock, good_socket_mock, ca, good_request):
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, bytes(json.dumps(req), encoding='utf-16'))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called

    csr = csr_from_str(req["csr_str"])
    assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_bad_request_missing(redis_mock, good_socket_mock, ca, bad_request_missing):
    # prepare env
    req = bad_request_missing
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))

    # test
    process(redis_mock, good_socket_mock, ca)

    # Check SN interaction
    assert not good_socket_mock.send_multipart.called
    # Check redis interaction
    assert not redis_mock.set.called

    if "csr_str" in req and "sn" in req:
        csr = csr_from_str(req["csr_str"])
        assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_fail_reply(redis_mock, socket_mock, ca, checker_fail_reply, good_request):
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_fail_reply

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert socket_mock.send_multipart.call_count == 1

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == "fail"

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert not ca.get_valid_cert_matching_csr(req["sn"], csr)


def test_process_bad_reply(redis_mock, socket_mock, ca, checker_error_reply, good_request):
    # prepare env
    req = good_request
    redis_mock.brpop.return_value = (1, dict_to_bytes(req))
    socket_mock.recv_multipart.return_value = checker_error_reply

    # test
    process(redis_mock, socket_mock, ca)

    # Check SN interaction
    assert socket_mock.send_multipart.call_count == 1

    # Check redis interaction
    assert redis_mock.set.call_count == 1
    # auth_state
    auth_state = bytes_to_dict(redis_mock.set.call_args_list[0][0][1])
    assert auth_state["status"] == "error"

    # Check certs in sqlite
    csr = csr_from_str(req["csr_str"])
    assert not ca.get_valid_cert_matching_csr(req["sn"], csr)
