"""
Test CA class
"""

import pytest

from sentinel_ca.ca import CA
from sentinel_ca.crypto import check_cert
from sentinel_ca.db import db_connection
from sentinel_ca.sn import prepare_config
from sentinel_ca.exceptions import CASetupError

from .crypto_helpers import \
        gen_key, \
        gen_cacert, \
        gen_expired_cacert, \
        gen_not_valid_yet_cacert, \
        key_to_bytes, \
        cert_to_bytes
from .db_helpers import prepare_db


def test_ca_key_cert_mismatch(tmpdir):
    key_path = tmpdir.join("key.pem")
    cert_path = tmpdir.join("cert.pem")
    db_path = tmpdir.join("ca.db")

    key = gen_key()
    wrong_key = gen_key()
    cert = gen_cacert(wrong_key)

    key_path.write(key_to_bytes(key))
    cert_path.write(cert_to_bytes(cert))

    prepare_db(str(db_path))

    # apply sentinel_ca config defaults
    ca_config = prepare_config()
    # use generated key, cert and db
    ca_config.set("ca", "cert", str(cert_path))
    ca_config.set("ca", "key", str(key_path))
    ca_config.set("db", "path", str(db_path))

    with db_connection(ca_config) as db:
        with pytest.raises(CASetupError):
            CA(ca_config, db)


@pytest.mark.parametrize(
        "gen_function",
        (
            gen_expired_cacert,
            gen_not_valid_yet_cacert,
        )
)
def test_check_cert(gen_function):
    key = gen_key()
    cert = gen_function(key)

    with pytest.raises(CASetupError):
        check_cert(cert, key)
