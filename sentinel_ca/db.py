"""
Data storage wrappers for Sentinel:CA
"""

import contextlib
import sqlite3

from .crypto import build_aki, cert_from_bytes, get_cert_bytes, get_cert_common_name, get_issuer_common_name
from .exceptions import CASetupError


@contextlib.contextmanager
def db_connection(conf):
    conn = sqlite3.connect(conf.get("db", "path"))

    try:
        # test table and columns existence
        with contextlib.closing(conn.cursor()) as c:
            c.execute("""
                    SELECT sn, state, common_name, not_before, not_after, ca_id, cert
                    FROM certs
                    LIMIT 1
                    """
            )
            c.execute("""
                    SELECT id, ca_name, issuer_name, not_before, not_after, authority_key_identifier, ca_cert
                    FROM ca
                    LIMIT 1
                    """
            )
        yield conn

    except sqlite3.OperationalError:
        raise CASetupError("Incorrect DB scheme")
    finally:
        conn.close()


def aki_to_str(aki):
    return aki.key_identifier.hex().upper()


def ca_exists_in_db(conn, ca_cert):
    return bool(get_ca_id(conn, ca_cert))


def get_ca_id(conn, ca_cert):
    ca_name = get_cert_common_name(ca_cert)
    authority_key_identifier = aki_to_str(build_aki(ca_cert))

    with contextlib.closing(conn.cursor()) as c:
        c.execute("""
                SELECT id
                FROM ca
                WHERE ca_name = ?
                    AND authority_key_identifier = ?
                LIMIT 1
                """,
                (ca_name, authority_key_identifier)
        )

        row = c.fetchone()
        if not row:
            return None
        return row[0]


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


def store_ca(conn, ca_cert):
    issuer_name = get_issuer_common_name(ca_cert)
    ca_name = get_cert_common_name(ca_cert)
    not_before = ca_cert.not_valid_before
    not_after = ca_cert.not_valid_after
    authority_key_identifier = aki_to_str(build_aki(ca_cert))
    cert_bytes = get_cert_bytes(ca_cert)

    with contextlib.closing(conn.cursor()) as c:
        c.execute("""
                INSERT INTO ca(issuer_name, ca_name, not_before, not_after, authority_key_identifier, ca_cert)
                VALUES (?,?,?,?,?,?)
                """,
                (issuer_name, ca_name, not_before, not_after, authority_key_identifier, cert_bytes)
        )
    conn.commit()


def store_cert(conn, cert, ca_id):
    serial_number = cert.serial_number
    identity = get_cert_common_name(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    cert_bytes = get_cert_bytes(cert)

    with contextlib.closing(conn.cursor()) as c:
        c.execute("""
                INSERT INTO certs(sn, state, common_name, not_before, not_after, ca_id, cert)
                VALUES (?,?,?,?,?,?,?)
                """,
                (str(serial_number), "valid", identity, not_before, not_after, ca_id, cert_bytes)
        )
    conn.commit()
