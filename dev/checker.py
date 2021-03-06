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
    "signature",
]

LOG_MESSAGE_MAPPER = {
    "incoming": "←",
    "outgoing": "→",
    "none": " ",
}


class CheckerClientError(Exception):
    pass


class CheckerServerError(Exception):
    pass


def get_argparser(parser):
    parser.add_argument(
            "-l", "--log-messages",
            action='store_true',
            help="Log incoming/outgoing messages"
    )
    return parser


def log_message(msg_type, message, direction="none", extra_line=False):
    symbol = LOG_MESSAGE_MAPPER[direction]
    print("{} {}: {}".format(symbol, msg_type, message))
    if extra_line:
        print("")


def check_message(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CheckerServerError("Unknown message type '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_KEYS:
        if key not in message:
            raise CheckerServerError("'{}' is missing in the message".format(key))


def process_message(device_id, nonce, signature):
    to_hash = "{}:{}".format(device_id, nonce)
    hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    if signature != hash_digest.hexdigest():
        raise CheckerClientError("Provided signature is not valid")


def build_reply(status, message=""):
    return {
        "status": status,
        "message": message,
    }


def process(msg_type, message):
    try:
        check_message(msg_type, message)
        process_message(message["sn"], message["nonce"], message["signature"])
        return build_reply("ok")
    except CheckerClientError as e:
        return build_reply("fail", str(e))
    except CheckerServerError as e:
        return build_reply("error", str(e))


def main():
    ctx = sn.SN(zmq.Context.instance(), get_argparser(sn.get_arg_parser()))
    socket = ctx.get_socket(("in", "REP"))

    # Receive the message, compare signature and reply with status (and error message)
    while True:
        zmq_msg = socket.recv_multipart()
        msg_type, message = sn.parse_msg(zmq_msg)
        if ctx.args.log_messages:
            log_message(msg_type, message, direction="incoming")

        reply = process(msg_type, message)

        if ctx.args.log_messages:
            log_message(msg_type, reply, direction="outgoing", extra_line=True)
        socket.send_multipart(sn.encode_msg(msg_type, reply))


if __name__ == "__main__":
    main()
