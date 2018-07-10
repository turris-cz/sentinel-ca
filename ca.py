#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import logging

import zmq
import sn

import sentinel_ca


logger = logging.getLogger("ca")


def process(r, socket, db, ca_key, ca_cert):
    try:
        request = sentinel_ca.get_request(r)
        sentinel_ca.check_request(request)
    except sentinel_ca.CAParseError as e:
        logger.error("Malformed request: %s", str(e))
        return

    try:
        sentinel_ca.check_auth(socket, request)
        cert = sentinel_ca.issue_cert(db, ca_key, ca_cert, request)
        sentinel_ca.store_cert(db, cert)

        logger.info(
                "Certificate with s/n %d for %s was issued",
                cert.serial_number,
                sentinel_ca.get_cert_common_name(cert)
        )
        reply = sentinel_ca.build_reply(cert)
    except sentinel_ca.CARequestError as e:
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
