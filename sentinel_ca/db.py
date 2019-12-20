"""
Data storage wrappers for Sentinel:CA
"""

import contextlib
import sqlite3

from .crypto import cert_from_bytes, get_cert_bytes, get_cert_common_name
from .exceptions import CASetupError


@contextlib.contextmanager
def db_connection(conf):
    conn = sqlite3.connect(conf.get("db", "path"))

    try:
        # test table and columns existence
        with contextlib.closing(conn.cursor()) as c:
            c.execute("""
                    SELECT sn, state, common_name, not_before, not_after, authority_key_identifier, cert
                    FROM certs
                    LIMIT 1
                    """
            )
        yield conn

    except sqlite3.OperationalError:
        raise CASetupError("Incorrect DB scheme")
    finally:
        conn.close()


def get_certs(conn, identity, date):
    """
    Iterator returning certs matching identity and valid at the date
    """
    with contextlib.closing(conn.cursor()) as c:
        c.execute("""
                SELECT cert
                FROM certs
                WHERE common_name = ?
                    AND not_before <= ?
                    AND ? <= not_after
                ORDER BY not_before DESC
                """,
                (identity, date, date)
        )

        for row in c:
            yield cert_from_bytes(row[0])


def store_cert(conn, cert, aki):
    serial_number = cert.serial_number
    identity = get_cert_common_name(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    cert_bytes = get_cert_bytes(cert)

    authority_key_identifier = aki.key_identifier.hex().upper()

    with contextlib.closing(conn.cursor()) as c:
        c.execute("""
                INSERT INTO certs(sn, state, common_name, not_before, not_after, authority_key_identifier, cert)
                VALUES (?,?,?,?,?,?,?)
                """,
                (str(serial_number), "valid", identity, not_before, not_after, authority_key_identifier, cert_bytes)
        )
    conn.commit()
