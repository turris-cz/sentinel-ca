"""
PyTest init, mocks and fixtures
"""

import contextlib
import sqlite3

import pytest

from sentinel_ca.sn import prepare_config


def prepare_db_scheme(db_path, scheme_path):
    with sqlite3.connect(db_path) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open(scheme_path) as scheme:
                c.executescript(scheme.read())
        conn.commit()


@pytest.fixture(params=[
     "tests/db/scheme_empty.sql",
     "tests/db/scheme_missing_column.sql",
     "tests/db/scheme_wrong_table_name.sql",
])
def db_config(tmpdir, request):
    db_path = tmpdir.join("empty.db")
    prepare_db_scheme(str(db_path), request.param)

    conf = prepare_config()
    conf.set("db", "path", str(db_path))

    return conf
