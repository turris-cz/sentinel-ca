"""
ZMQ and Sentinel Network functions for Sentinel:CA
"""

import sn

from .exceptions import CAParseError, CARequestError


MESSAGE_TYPE = "sentinel/certificator/checker"
AUTH_REQUEST_KEYS = [
    "sn",
    "auth_type",
    "nonce",
    "digest",
]
REQUIRED_AUTH_REPLY_KEYS = [
    "status",
    "message",
]


def check_auth_reply(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CARequestError("Unknown message type in auth reply '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_AUTH_REPLY_KEYS:
        if key not in message:
            raise CARequestError("'{}' is missing in the auth reply".format(key))


def check_auth(socket, request):
    auth_request = {key:request[key] for key in AUTH_REQUEST_KEYS}
    socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, auth_request))
    logger.debug("ZMQ send %s: %s", MESSAGE_TYPE, auth_request)

    zmq_reply = socket.recv_multipart()
    msg_type, auth_reply = sn.parse_msg(zmq_reply)
    logger.debug("ZMQ recv %s: %s", msg_type, auth_reply)

    check_auth_reply(msg_type, auth_reply)
    if auth_reply["status"] != "ok":
        raise CARequestError(auth_reply["message"])
