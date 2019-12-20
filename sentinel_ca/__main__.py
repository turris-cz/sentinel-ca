"""
Main entry point of Sentinel:CA package
"""

import logging

import sn

from .ca import CA
from .crypto import check_csr, csr_from_str
from .db import db_connection
from .exceptions import CAParseError, CARequestClientError, CARequestServerError
from .redis import init_redis, get_request, check_request, set_cert, set_auth_ok, set_auth_fail, set_auth_error
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
        # if anything fails, CARequestServerError is risen
        csr = csr_from_str(request["csr_str"])
        check_csr(csr, request["sn"])
        check_auth(socket, request)

        # do not look for a valid certificate if the renew flag is present
        if "renew" in request["flags"]:
            logger.debug("The request forced certificate renew")
            cert = None
        else:
            cert = ca.get_valid_cert_matching_csr(request["sn"], csr)

        if cert:
            # restore the cert if valid one is found
            message = "Old certificate was served"
            logger.info("Certificate for %s is served", request["sn"])
        else:
            # issue a new cert when none is found or renew is requested
            cert = ca.issue_cert(csr, request["sn"])
            message = "Certificate was issued"
            logger.info(
                    "Certificate with s/n %d for %s was issued",
                    cert.serial_number,
                    request["sn"]
            )

        set_cert(r, request["sn"], cert)
        set_auth_ok(r, request["sn"], request["sid"], message)

    except CARequestClientError as e:
        logger.warning("Failed request: %s", str(e))
        set_auth_fail(r, request["sn"], request["sid"], str(e))

    except CARequestServerError as e:
        logger.error("Invalid request: %s", str(e))
        set_auth_error(r, request["sn"], request["sid"], str(e))


def main():
    logger.info("Sentinel:CA starts")
    ctx, socket = init_sn()
    conf = config(ctx.args.config)

    r = init_redis(conf)

    with db_connection(conf) as db:
        ca = CA(conf, db, ctx.args.ca_ignore_errors)

        while True:
            process(r, socket, ca)


if __name__ == "__main__":
    main()
