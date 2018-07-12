"""
Main entry point of Sentinel:CA package
"""

import logging

import zmq
import sn

from .crypto import init_ca, issue_cert, get_cert_common_name
from .db import init_db, store_cert
from .exceptions import CAParseError, CARequestError
from .parser import get_argparser, config
from .redis import init_redis, get_request, check_request, build_reply, build_error, send_reply, redis_cert_key
from .sn import check_auth

logger = logging.getLogger("ca")


def init():
    ctx = sn.SN(
            zmq.Context.instance(),
            get_argparser(sn.get_arg_parser())
    )
    socket = ctx.get_socket(("checker", "REQ"))

    ca_cert, ca_key = init_ca(
            ctx.args.ca_cert,
            ctx.args.ca_key,
            ignore_errors=ctx.args.ca_ignore_errors
    )

    conf = config(ctx.args.config)
    r = init_redis(conf)
    db = init_db(conf)

    return r, socket, db, ca_key, ca_cert


def process(r, socket, db, ca_key, ca_cert):
    try:
        request = get_request(r)
        check_request(request)
    except CAParseError as e:
        logger.error("Malformed request: %s", str(e))
        return

    try:
        check_auth(socket, request)
        cert = issue_cert(db, ca_key, ca_cert, request)
        store_cert(db, cert)

        logger.info(
                "Certificate with s/n %d for %s was issued",
                cert.serial_number,
                get_cert_common_name(cert)
        )
        reply = build_reply(cert)
    except CARequestError as e:
        logger.error("Invalid request: %s", str(e))
        reply = build_error(str(e))

    redis_key = redis_cert_key(request)
    send_reply(r, redis_key, reply)


def run():
    logger.info("Sentinel:CA starts")
    r, socket, db, ca_key, ca_cert = init()
    while True:
        process(r, socket, db, ca_key, ca_cert)
