"""
Sentinel:CA certificate authority class
"""

import datetime
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# to setup logger handlers
import sn

from .exceptions import CAError, CASetupError
from .crypto import *
from .db import get_certs, store_cert, row_with_serial_number

logger = logging.getLogger("ca")


# default certificate validity
CERT_DAYS = 60
# 25% before end of validity
VALID_DAYS = int(0.25*CERT_DAYS)
# The HashAlgorithm instance used to sign the certificates
SIGNING_HASH = hashes.SHA256()


class CA:
    def __init__(self, conf, db, ignore_errors=False):
        self.db = db

        cert_path = conf.get("ca", "cert")
        key_path = conf.get("ca", "key")
        if conf.get("ca", "password"):
            key_password = bytes(conf.get("ca", "password"), encoding='utf-8')
        else:
            key_password = None

        with open(cert_path, 'rb') as f:
            self.cert = x509.load_pem_x509_certificate(
                    data=f.read(),
                    backend=default_backend()
            )
        with open(key_path, 'rb') as f:
            self.key = serialization.load_pem_private_key(
                    data=f.read(),
                    password=key_password,
                    backend=default_backend()
            )


        self.aki = build_aki(self.cert)
        try:
            check_cert(self.cert, self.key)
        except CASetupError as e:
            logger.error(str(e))
            if not ignore_errors:
                raise


    def get_valid_cert_matching_csr(self, identity, csr, days=VALID_DAYS):
        date = datetime.datetime.utcnow() + datetime.timedelta(days=days)
        for cert in get_certs(self.db, identity, date):
            if key_match(cert, csr):
                return cert
        return None


    def issue_cert(self, csr, identity, days=CERT_DAYS):
        serial_number = self.get_unique_serial_number()
        not_before = datetime.datetime.utcnow()
        not_after = not_before + datetime.timedelta(days=days)
        # raise a CAError when CA cert will not be valid till not_after
        self.check_cert_valid_at(not_after)

        cert = build_client_cert(
                csr=csr,
                serial_number=serial_number,
                subject=build_subject(identity),
                issuer=self.cert.subject,
                aki=self.aki,
                not_before=not_before,
                not_after=not_after,
        )
        cert = cert.sign(self.key, SIGNING_HASH, default_backend())
        store_cert(self.db, cert)

        return cert


    def check_cert_valid_at(self, at):
        if self.cert.not_valid_after < at:
            raise CAError("CA cert will expire sooner than requested")


    def get_unique_serial_number(self):
        # random_serial_number() gives unique values when everything is ok
        # repeated s/n generation and check for accidental generation and/or OS issues
        for i in range(42):
            serial_number = x509.random_serial_number()
            if row_with_serial_number(self.db, serial_number):
                logger.warning("random_serial_number() returns duplicated s/n")
                continue
            return serial_number

        raise CAError("Could not get unique certificate s/n")
