"""
Main entry point of Sentinel:CA package
"""

import logging

import sn

from .ca import CA
from .crypto import check_csr, load_csr
from .db import init_db
from .exceptions import CAParseError, CARequestError
from .redis import init_redis, get_request, check_request, set_cert, set_auth_ok, set_auth_failed
from .sn import check_auth, config, init_sn

logger = logging.getLogger("ca")


def process(r, socket, ca):
    try:
        request = get_request(r)
        check_request(request)
    except CAParseError as e:
        logger.error("Malformed request: %s", str(e))
        return

    try:
        # if anything fails, CARequestError is risen
        csr = load_csr(request["csr_str"])
        check_csr(csr, request["sn"])
        check_auth(socket, request)

        cert = ca.get_valid_cert_matching_csr(request["sn"], csr)
        if cert:
            logger.info("Certificate for %s is served", request["sn"])
        else:
            cert = ca.issue_cert(csr, request["sn"])
            logger.info(
                    "Certificate with s/n %d for %s was issued",
                    cert.serial_number,
                    request["sn"]
            )

        set_cert(r, request["sn"], cert)
        set_auth_ok(r, request["sn"], request["sid"])

    except CARequestError as e:
        logger.error("Invalid request: %s", str(e))
        set_auth_failed(r, request["sn"], request["sid"], str(e))


def run():
    logger.info("Sentinel:CA starts")
    ctx, socket = init_sn()
    conf = config(ctx.args.config)

    r = init_redis(conf)
    db = init_db(conf)
    ca = CA(conf, db, ctx.args.ca_ignore_errors)

    while True:
        process(r, socket, ca)
