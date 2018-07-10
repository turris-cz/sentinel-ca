#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import logging

import zmq
import sn

import sentinel_ca


logger = logging.getLogger("ca")

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


"""checker via zmq"""
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


def process(r, socket, db, ca_key, ca_cert):
    try:
        request = sentinel_ca.get_request(r)
        sentinel_ca.check_request(request)
    except CAParseError as e:
        logger.error("Malformed request: %s", str(e))
        return

    try:
        check_auth(socket, request)
        cert = sentinel_ca.issue_cert(db, ca_key, ca_cert, request)
        sentinel_ca.store_cert(db, cert)

        logger.info(
                "Certificate with s/n %d for %s was issued",
                cert.serial_number,
                sentinel_ca.get_cert_common_name(cert)
        )
        reply = sentinel_ca.build_reply(cert)
    except CARequestError as e:
        logger.error("Invalid request: %s", str(e))
        reply = sentinel_ca.build_error(str(e))

    redis_key = sentinel_ca.redis_cert_key(request)
    sentinel_ca.send_reply(r, redis_key, reply)


def main():
    ctx = sn.SN(
            zmq.Context.instance(),
            sentinel_ca.get_argparser(sn.get_arg_parser())
    )
    socket = ctx.get_socket(("checker", "REQ"))

    ca_cert, ca_key = sentinel_ca.init_ca(
            ctx.args.ca_cert,
            ctx.args.ca_key,
            ignore_errors=ctx.args.ca_ignore_errors
    )

    conf = sentinel_ca.config(ctx.args.config)
    r = sentinel_ca.init_redis(conf)
    db = sentinel_ca.init_db(conf)

    while True:
        process(r, socket, db, ca_key, ca_cert)


if __name__ == "__main__":
    main()
