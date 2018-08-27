"""
Reusable functions for CA class
"""

from sentinel_ca.sn import prepare_config

from .crypto_helpers import gen_key, gen_cacert, gen_soon_to_be_expired_cacert, key_to_bytes, cert_to_bytes
from .db_helpers import prepare_db


def build_ca_config(tmpdir, expire_soon=False, wrong_key=False):
    # Generate the key
    key_path = tmpdir.join("key.pem")
    key = gen_key()
    key_path.write(key_to_bytes(key))

    # Generate the cert
    cert_path = tmpdir.join("cert.pem")

    # generate wrong key if desired
    if wrong_key:
        key = gen_key()

    # generate soon-to-be-expired cert if desired
    if expire_soon:
        cert = gen_soon_to_be_expired_cacert(key)
    else:
        cert = gen_cacert(key)

    cert_path.write(cert_to_bytes(cert))

    # Generate the db
    db_path = tmpdir.join("ca.db")
    prepare_db(str(db_path))

    # Build the config
    # apply sentinel_ca config defaults
    conf = prepare_config()
    # use generated key, cert and db
    conf.set("ca", "cert", str(cert_path))
    conf.set("ca", "key", str(key_path))
    conf.set("db", "path", str(db_path))

    return conf
