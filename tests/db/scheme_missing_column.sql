---- scheme.sql
--
-- A scheme to test missing column
CREATE TABLE certs (
    id INTEGER PRIMARY KEY,
    sn TEXT UNIQUE NOT NULL,
    common_name TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert BLOB NOT NULL
)
