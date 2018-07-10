"""
Cryptography-related tasks for Sentinel:CA
"""

import datetime
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
# signing certs
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes

from .exceptions import CAError, CASetupError, CARequestError


CERT_DAYS = 30
SIGNING_HASH = hashes.SHA256()

ALLOWED_HASHES = {
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
}


def build_aki(issuer):
    try:
        # construct AKI from issuer Subject Key Identifier if it has some
        ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)

    except x509.ExtensionNotFound:
        # construct AKI from public key if issuer does not have SKI
        public_key = issuer.public_key()
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)

    return aki


def build_subject(identity):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, identity),
    ])


def build_client_cert(csr, serial_number, subject, issuer, aki, not_before, not_after):
    # Generate v1 cert (without extensions) ----------
    cert = x509.CertificateBuilder(
            issuer_name=issuer,
            subject_name=subject,
            public_key=csr.public_key(),
            serial_number=serial_number,
            not_valid_before=not_before,
            not_valid_after=not_after,
    )

    # Add needed extensions --------------------------
    # key identifiers
    cert = cert.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
    )
    cert = cert.add_extension(
            aki,
            critical=False
    )

    # critical Basic Constraints
    cert = cert.add_extension(
            x509.BasicConstraints(
                    ca=False,
                    path_length=None
            ),
            critical=True
    )

    # "Digital Signature" Key Usage
    cert = cert.add_extension(
            x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
            ),
            critical=False
    )

    # "Client" ExtendedKeyUsage
    cert = cert.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
    )

    return cert


def check_cert_private_key_match(cert, key):
    cert_key = cert.public_key()
    public_key = key.public_key()

    if public_key.public_numbers() != cert_key.public_numbers():
        raise CASetupError("Private key does not match with certificate public key")


def check_cert_valid_dates(cert):
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        raise CASetupError("Certificate is not valid yet")

    if cert.not_valid_after < now:
        raise CASetupError("Certificate is expired")


def check_cert_basic_constraints(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise CASetupError("Certificate does not have Basic Constraints extension")

    if not ext.value.ca:
        raise CASetupError("Certificate is not a CA cert")


def check_cert_key_usage(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        raise CASetupError("Certificate does not have Key Usage extension")

    if not ext.value.key_cert_sign:
        raise CASetupError("CA key usage does not allow cert signing")


def check_cert_subject_key_identifier(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        raise CASetupError("Certificate does not have Subject Key Identifier extension")


def check_cert(cert, key, ignore_errors):
    try:
        check_cert_private_key_match(cert, key)
        check_cert_basic_constraints(cert)
        check_cert_key_usage(cert)
        check_cert_subject_key_identifier(cert)
        # TODO what if it expire soon?
        check_cert_valid_dates(cert)

    except CASetupError as e:
        print(str(e), file=sys.stderr)
        if not ignore_errors:
            sys.exit(2)


def check_csr_common_name(csr, identity):
    common_names = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise CARequestError("CSR has not exactly one CommonName")

    common_name = common_names[0].value
    if common_name != identity:
        raise CARequestError("CSR CommonName ({}) does not match desired identity".format(common_name))


def check_csr_hash(csr):
    h = csr.signature_hash_algorithm
    if type(h) not in ALLOWED_HASHES:
        raise CARequestError("CSR is signed with not allowed hash ({})".format(h.name))


def check_csr_signature(csr):
    if not csr.is_signature_valid:
        raise CARequestError("Request signature is not valid")


def check_csr(csr, device_id):
    check_csr_common_name(csr, device_id)
    check_csr_hash(csr)
    check_csr_signature(csr)


def get_cert_common_name(cert):
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        # catch all Exceptions as the x509 certificate interface is not so clean
        logger.exception("Common name is not present")
        common_name = "N/A"

    return common_name


"""Generate random serial number and ensure it is not used yet"""
def get_unique_serial_number(db):
    # random_serial_number() gives unique values when everything is ok
    # repeated s/n generation and check for accidental generation and/or OS issues
    for i in range(42):
        serial_number = x509.random_serial_number()

        c = db.cursor()
        c.execute('SELECT * FROM certs WHERE sn=?', (str(serial_number),))
        if c.fetchone():
            c.close()
            logger.warning("random_serial_number() returns duplicated s/n")
            continue

        # if there is no cert with this S/N
        c.close()
        return serial_number

    # this exception will not be handled
    raise CAError("Could not get unique certificate s/n")


def init_ca(cert_path, key_path, key_password=None, ignore_errors=False):
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(
                data=f.read(),
                backend=default_backend()
        )
    with open(key_path, 'rb') as f:
        key = serialization.load_pem_private_key(
                data=f.read(),
                password=key_password,
                backend=default_backend()
        )
    check_cert(cert, key, ignore_errors)

    return cert, key


def issue_cert(db, ca_key, ca_cert, request):
    csr = load_csr(request["csr_str"])
    identity = request["sn"]

    check_csr(csr, identity)

    serial_number = get_unique_serial_number(db)
    not_before = datetime.datetime.utcnow()
    not_after = datetime.datetime.utcnow() + datetime.timedelta(days=CERT_DAYS)

    cert = build_client_cert(
            csr=csr,
            serial_number=serial_number,
            subject=build_subject(identity),
            issuer=ca_cert.subject,
            aki=build_aki(ca_cert),
            not_before=not_before,
            not_after=not_after,
    )
    cert = cert.sign(ca_key, SIGNING_HASH, default_backend())

    return cert


def load_csr(csr_str):
    try:
        # construct x509 request from PEM string
        csr_data = bytes(csr_str, encoding='utf-8')
        csr = x509.load_pem_x509_csr(
                data=csr_data,
                backend=default_backend()
        )
    except (UnicodeEncodeError, ValueError):
        raise CARequestError("Invalid CSR format")

    return csr
