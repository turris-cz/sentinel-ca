---- scheme.sql
--
-- A scheme for certificate list
CREATE TABLE IF NOT EXISTS certs (
    id INTEGER PRIMARY KEY,
    sn TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('valid', 'revoked')),
    common_name TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    authority_key_identifier TEXT NOT NULL,
    cert BLOB NOT NULL
);
