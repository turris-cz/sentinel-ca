"""
PyTest init, mocks and fixtures
"""
import sys
sys.path.append("..")

from unittest.mock import Mock

import pytest

from sentinel_ca.db import db_connection
from sentinel_ca.ca import CA
from sentinel_ca.sn import prepare_config

from .crypto_helpers import gen_key, gen_cacert, gen_soon_to_be_expired_cacert, key_to_bytes, cert_to_bytes
from .db_helpers import prepare_db
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
def ca_config(tmpdir):
    key_path = tmpdir.join("key.pem")
    cert_path = tmpdir.join("cert.pem")
    db_path = tmpdir.join("ca.db")

    key = gen_key()
    cert = gen_cacert(key)

    key_path.write(key_to_bytes(key))
    cert_path.write(cert_to_bytes(cert))

    prepare_db(str(db_path))

    # apply sentinel_ca config defaults
    conf = prepare_config()
    # use generated key, cert and db
    conf.set("ca", "cert", str(cert_path))
    conf.set("ca", "key", str(key_path))
    conf.set("db", "path", str(db_path))

    return conf


@pytest.fixture
def ca_config_expire_soon(tmpdir):
    key_path = tmpdir.join("key.pem")
    cert_path = tmpdir.join("cert.pem")
    db_path = tmpdir.join("ca.db")

    key = gen_key()
    cert = gen_soon_to_be_expired_cacert(key)

    key_path.write(key_to_bytes(key))
    cert_path.write(cert_to_bytes(cert))

    prepare_db(str(db_path))

    # apply sentinel_ca config defaults
    conf = prepare_config()
    # use generated key, cert and db
    conf.set("ca", "cert", str(cert_path))
    conf.set("ca", "key", str(key_path))
    conf.set("db", "path", str(db_path))

    return conf


@pytest.fixture
def ca(ca_config):
    with db_connection(ca_config) as db:
        yield CA(ca_config, db)


@pytest.fixture
def ca_expire_soon(ca_config_expire_soon):
    with db_connection(ca_config_expire_soon) as db:
        yield CA(ca_config_expire_soon, db)
