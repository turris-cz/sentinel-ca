---- scheme.sql
--
-- A scheme to test wrong table name
CREATE TABLE cert (
    id INTEGER PRIMARY KEY,
    sn TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('valid', 'revoked')),
    common_name TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert BLOB NOT NULL
);
