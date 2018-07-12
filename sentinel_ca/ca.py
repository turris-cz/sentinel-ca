"""
Sentinel:CA certificate authority class
"""

import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .exceptions import CASetupError
from .crypto import *
from .db import store_cert

CERT_DAYS = 30
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


    def issue_cert(self, csr_str, identity):
        csr = load_csr(csr_str)
        check_csr(csr, identity)

        serial_number = get_unique_serial_number(self.db)
        not_before = datetime.datetime.utcnow()
        not_after = not_before + datetime.timedelta(days=CERT_DAYS)

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