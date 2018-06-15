#!/usr/bin/env python3
## checker.py
#
# dummy implementation of checker: a certificator component

import hashlib

import zmq
import sn


MESSAGE_TYPE = "sentinel/certificator/checker"
REQUIRED_KEYS = [
    "auth_type",
    "sn",
    "nonce",
    "digest",
]


class CheckerError(Exception):
    pass


def check_message(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CheckerError("Unknown message type '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_KEYS:
        if key not in message:
            raise CheckerError("'{}' is missing in the message".format(key))


def process_message(sn, nonce, digest):
    to_hash = "{}:{}".format(sn, nonce)
    hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    if digest != hash_digest.hexdigest():
        raise CheckerError("Provided digest is not valid")


def build_reply(status, message=""):
    return {
        "status": status,
        "message": message,
    }


def main():
    ctx = sn.SN(zmq.Context.instance())
    socket = ctx.get_socket(("in", "REP"))

    # Receive the message, compare digest and reply with status (and error message)
    while True:
        zmq_msg = socket.recv_multipart()
        msg_type, message = sn.parse_msg(zmq_msg)

        try:
            check_message(msg_type, message)
            process_message(message["sn"], message["nonce"], message["digest"])
            reply = build_reply("ok")
        except CheckerError as e:
            zmq_reply = build_reply("failed", str(e))

        socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, reply))


if __name__ == "__main__":
    main()
