---- scheme.sql
--
-- A scheme for certificate lists
CREATE TABLE IF NOT EXISTS certs (
    id INTEGER PRIMARY KEY,
    sn TEXT UNIQUE NOT NULL,
    common_name TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert BLOB NOT NULL
)