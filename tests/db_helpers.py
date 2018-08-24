"""
Reusable db-related functions
"""

import contextlib
import sqlite3


def prepare_db(db_path):
    with sqlite3.connect(db_path) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open("scheme.sql") as scheme:
                c.executescript(scheme.read())
        conn.commit()
