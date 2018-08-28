"""
PyTest init, mocks and fixtures
"""

import pytest

from sentinel_ca.sn import prepare_config

from ..helpers import prepare_db_scheme


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
