"""
Reusable functions for tests
"""

import contextlib
import json
import sqlite3

import sn

from sentinel_ca.sn import prepare_config

from .crypto_helpers import gen_key, gen_cacert, gen_soon_to_be_expired_cacert, key_to_bytes, cert_to_bytes


def dict_to_bytes(d):
    return bytes(json.dumps(d), encoding='utf-8')


def bytes_to_dict(b):
    return json.loads(str(b), encoding='utf-8')


def prepare_db_scheme(db_path, scheme_path="scheme.sql"):
    with sqlite3.connect(db_path) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open(scheme_path) as scheme:
                c.executescript(scheme.read())
        conn.commit()


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
    prepare_db_scheme(str(db_path))

    # Build the config
    # apply sentinel_ca config defaults
    conf = prepare_config()
    # use generated key, cert and db
    conf.set("ca", "cert", str(cert_path))
    conf.set("ca", "key", str(key_path))
    conf.set("db", "path", str(db_path))

    return conf


def build_checker_reply(status="ok", message="", msg_type="sentinel/certificator/checker"):
    # add status and message to the payload if they are not None
    msg_payload = {}
    if status is not None:
        msg_payload["status"] = status
    if message is not None:
        msg_payload["message"] = message

    return sn.encode_msg(msg_type, msg_payload)
