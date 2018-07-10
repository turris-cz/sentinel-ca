"""
Data storage wrappers for Sentinel:CA
"""

import sqlite3

from .crypto import get_cert_bytes, get_cert_common_name
from .exceptions import CASetupError


def init_db(conf):
    conn = sqlite3.connect(conf.get("db", "path"))

    try:
        # test table and columns existence
        c = conn.cursor()
        c.execute("""
                SELECT sn, state, common_name, not_before, not_after, cert
                  FROM certs
                  LIMIT 1
        """)
        c.close()
    except sqlite3.OperationalError:
        raise CASetupError("Incorrect DB scheme")

    return conn


def store_cert(db, cert):
    serial_number = cert.serial_number
    identity = get_cert_common_name(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    cert_bytes = get_cert_bytes(cert)

    c = db.cursor()
    c.execute("""
            INSERT INTO certs(sn, state, common_name, not_before, not_after, cert)
            VALUES (?,?,?,?,?,?)
            """,
            (str(serial_number), "valid", identity, not_before, not_after, cert_bytes)
    )
    c.close()
    db.commit()
