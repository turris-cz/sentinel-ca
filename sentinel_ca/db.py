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
                    SELECT sn, state, common_name, not_before, not_after, cert
                    FROM certs
                    LIMIT 1
            """)
        yield conn

    except sqlite3.OperationalError:
        raise CASetupError("Incorrect DB scheme")
    finally:
        conn.close()


def get_certs(db, identity, date):
    with contextlib.closing(db.cursor()) as c:
        c.execute("""
                SELECT cert
                  FROM certs
                  WHERE common_name = ? AND
                        not_before <= ? AND
                        ? <= not_after
                  ORDER BY not_before DESC
                """,
                (identity, date, date)
        )

        for row in c:
            yield cert_from_bytes(row[0])


def store_cert(db, cert):
    serial_number = cert.serial_number
    identity = get_cert_common_name(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    cert_bytes = get_cert_bytes(cert)

    with contextlib.closing(db.cursor()) as c:
        c.execute("""
                INSERT INTO certs(sn, state, common_name, not_before, not_after, cert)
                  VALUES (?,?,?,?,?,?)
                """,
                (str(serial_number), "valid", identity, not_before, not_after, cert_bytes)
        )
    db.commit()


def row_with_serial_number(db, serial_number):
    with contextlib.closing(db.cursor()) as c:
        c.execute('SELECT * FROM certs WHERE sn=?', (str(serial_number),))
        return c.fetchone()
