"""
PyTest init, mocks and fixtures
"""
import sys
sys.path.append("..")

import contextlib
import sqlite3
from unittest.mock import Mock

import pytest

from sentinel_ca.ca import CA
from sentinel_ca.sn import prepare_config

from .crypto_helpers import pregen_key, pregen_cert

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
def db(tmpdir):
    db_path = tmpdir.join("ca.db")
    with sqlite3.connect(str(db_path)) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open("scheme.sql") as scheme:
                c.executescript(scheme.read())
        conn.commit()
        yield conn


@pytest.fixture
def ca_config(tmpdir):
    key_path = tmpdir.join("key.pem")
    cert_path = tmpdir.join("cert.pem")

    key_path.write(pregen_key())
    cert_path.write(pregen_cert())

    # apply sentinel_ca config defaults
    conf = prepare_config()
    # use generated key, cert and db
    conf.set("ca", "cert", str(cert_path))
    conf.set("ca", "key", str(key_path))

    return conf


@pytest.fixture
def ca(ca_config, db):
    return CA(ca_config, db)
