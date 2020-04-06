"""
Sentinel:CA certificate authority class
"""

import datetime
import logging

# to setup logger handlers
import sn

from .exceptions import CAError, CASetupError
from .crypto import build_aki, build_client_cert, build_subject, cert_from_file, check_cert, key_from_file, key_match, random_serial_number, sign_cert
from .db import ca_exists_in_db, get_ca_id, get_certs, store_ca, store_cert

logger = logging.getLogger("ca")


class CA:
    def __init__(self, conf, db, ignore_errors=False):
        cert_path = conf.get("ca", "cert")
        key_path = conf.get("ca", "key")
        if conf.get("ca", "password"):
            key_password = bytes(conf.get("ca", "password"), encoding='utf-8')
        else:
            key_password = None

        self.cert = cert_from_file(cert_path)
        self.key = key_from_file(key_path, key_password)
        self.aki = build_aki(self.cert)

        try:
            check_cert(self.cert, self.key)
        except CASetupError as e:
            logger.error(str(e))
            if not ignore_errors:
                raise

        valid_days = conf.getint("ca", "valid_days")
        valid_days_min = conf.getint("ca", "valid_days_min")
        self.valid_days = datetime.timedelta(days=valid_days)
        self.valid_days_min = datetime.timedelta(days=valid_days_min)

        self.db = db
        if not ca_exists_in_db(self.db, self.cert):
            store_ca(self.db, self.cert)
        self.id = get_ca_id(self.db, self.cert)


    def get_valid_cert_matching_csr(self, identity, csr):
        """
        Return certificate for the common name 'identity' matching public key
        in the request 'csr' and that would be valid for at least
        (preconfigured attribute) 'valid_days_min'
        """
        date = datetime.datetime.utcnow() + self.valid_days_min
        for cert in get_certs(self.db, identity, date):
            if key_match(cert, csr):
                return cert
        return None


    def issue_cert(self, csr, identity):
        serial_number = random_serial_number()
        not_before = datetime.datetime.utcnow()
        not_after = not_before + self.valid_days
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
        cert = sign_cert(cert, self.key)
        store_cert(self.db, cert, self.id)

        return cert


    def check_cert_valid_at(self, at):
        if self.cert.not_valid_after < at:
            raise CAError("CA cert will expire sooner than requested")
