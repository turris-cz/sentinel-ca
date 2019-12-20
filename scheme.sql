---- scheme.sql
--
-- A scheme for Sentinel:CA

CREATE TABLE IF NOT EXISTS ca (
    id INTEGER PRIMARY KEY,
    issuer_name TEXT NOT NULL UNIQUE,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    authority_key_identifier TEXT NOT NULL UNIQUE,
    ca_cert BLOB NOT NULL
);

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
