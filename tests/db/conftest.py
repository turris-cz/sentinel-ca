"""
PyTest init, mocks and fixtures
"""

import contextlib
import sqlite3

import pytest

from sentinel_ca.sn import prepare_config


def prepare_db_empty(db_path):
    pass


def prepare_db_missing_column(db_path):
    with sqlite3.connect(db_path) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open("tests/db/scheme_missing_column.sql") as scheme:
                c.executescript(scheme.read())
        conn.commit()


def prepare_db_wrong_table_name(db_path):
    with sqlite3.connect(db_path) as conn:
        with contextlib.closing(conn.cursor()) as c:
            with open("tests/db/scheme_wrong_table_name.sql") as scheme:
                c.executescript(scheme.read())
        conn.commit()


@pytest.fixture
def db_config_empty(tmpdir):
    db_path = tmpdir.join("empty.db")
    prepare_db_empty(str(db_path))

    conf = prepare_config()
    conf.set("db", "path", str(db_path))

    return conf


@pytest.fixture
def db_config_missing_column(tmpdir):
    db_path = tmpdir.join("missing.db")
    prepare_db_missing_column(str(db_path))

    conf = prepare_config()
    conf.set("db", "path", str(db_path))

    return conf


@pytest.fixture
def db_config_wrong_table_name(tmpdir):
    db_path = tmpdir.join("wrong.db")
    prepare_db_wrong_table_name(str(db_path))

    conf = prepare_config()
    conf.set("db", "path", str(db_path))

    return conf
