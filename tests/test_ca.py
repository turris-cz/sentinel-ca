"""
Test CA class
"""

import pytest

from sentinel_ca.ca import CA
from sentinel_ca.crypto import check_cert
from sentinel_ca.db import db_connection
from sentinel_ca.exceptions import CASetupError

from .helpers import build_ca_config
from .crypto_helpers import \
        gen_key, \
        gen_expired_cacert, \
        gen_not_valid_yet_cacert, \
        gen_no_basic_constraints_cacert, \
        gen_false_basic_constraints_cacert, \
        gen_no_key_usage_cacert, \
        gen_false_key_usage_cacert, \
        gen_no_key_identifiers_cacert


def test_ca_key_cert_mismatch(tmpdir):
    ca_config = build_ca_config(tmpdir, wrong_key=True)
    with db_connection(ca_config) as db:
        with pytest.raises(CASetupError):
            CA(ca_config, db)


@pytest.mark.parametrize(
        "gen_function",
        (
            gen_expired_cacert,
            gen_not_valid_yet_cacert,
            gen_no_basic_constraints_cacert,
            gen_false_basic_constraints_cacert,
            gen_no_key_usage_cacert,
            gen_false_key_usage_cacert,
            gen_no_key_identifiers_cacert,
        )
)
def test_check_cert(gen_function):
    key = gen_key()
    cert = gen_function(key)

    with pytest.raises(CASetupError):
        check_cert(cert, key)
