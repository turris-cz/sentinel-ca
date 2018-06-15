import pytest

import hashlib

import checker


MESSAGE_TYPE = "sentinel/certificator/checker"


def msg_payload(sn, nonce, good_digest=True):
    if good_digest:
        to_hash = "{}:{}".format(sn, nonce)
        hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
        digest = hash_digest.hexdigest()
    else:
        digest = "d3ADbE3F0042"

    msg = {
        "auth_type": "atsha",
        "sn": sn,
        "nonce": nonce,
        "digest": digest,
    }

    return msg


def test_normal_processing():
    reply = checker.process(MESSAGE_TYPE, msg_payload("foo", 65487654))

    assert reply["status"] == "ok"
    assert reply["message"] == ""


def test_bad_msg_type():
    reply = checker.process("sentinel/ca",  msg_payload("foo", 65487654))

    assert reply["status"] == "failed"
    assert "Unknown message type" in reply["message"]


def test_missing_msg_part():
    p = msg_payload("foo", 65487654)
    del p["sn"]

    reply = checker.process(MESSAGE_TYPE, p)

    assert reply["status"] == "failed"
    assert "missing in the message" in reply["message"]


def test_bad_digest():
    reply = checker.process(MESSAGE_TYPE, msg_payload("foo", 65487654, good_digest=False))
    print(reply)

    assert reply["status"] == "failed"
    assert "Provided digest is not valid" in reply["message"]
