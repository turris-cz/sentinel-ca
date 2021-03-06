"""
Reusable functions for cryptography stuff
"""

import datetime
import hashlib
import os
import time

# backend
from cryptography.hazmat.backends import default_backend
# serialization
from cryptography.hazmat.primitives import serialization
# private/public keys
from cryptography.hazmat.primitives.asymmetric import ec
# request
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


ECDSA_CURVE = ec.SECP256R1()


def build_subject(identity):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, identity),
    ])


def key_to_bytes(private_key):
    return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )


def cert_to_bytes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def add_basic_contraints(cert, value):
    """Returns 'cert' with added BasicConstraints critical extension with
    ca set to 'value'
    """
    return cert.add_extension(
            x509.BasicConstraints(
                    ca=value,
                    path_length=None
            ),
            critical=True
    )


def add_key_usage(cert, value):
    """Returns 'cert' with added KeyUsage extension with key_cert_sign and
    crl_sign set to 'value'
    """
    return cert.add_extension(
            x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=value,
                    crl_sign=value,
                    encipher_only=False,
                    decipher_only=False
            ),
            critical=False
    )


def add_key_identifiers(cert, private_key):
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
            ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
    )
    cert = cert.add_extension(ski, critical=False)
    cert = cert.add_extension(aki, critical=False)

    return cert


def gen_key(curve=ECDSA_CURVE):
    return ec.generate_private_key(
            curve=curve,
            backend=default_backend()
    )


def gen_csr(device_id, valid_hash=True):
    private_key = gen_key()

    subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    csr = x509.CertificateSigningRequestBuilder(subject_name=subject)
    if valid_hash:
        csr = csr.sign(private_key, hashes.SHA256(), default_backend())
    else:
        csr = csr.sign(private_key, hashes.SHA1(), default_backend())

    return csr


def gen_cacert(
        private_key,
        not_before=None,
        not_after=None,
        ext_key_usage=True,
        ext_basic_constraints=True,
        ext_key_identifiers=True,
        common_name="Fake Sentinel:CA for pytest"
):
    subject = build_subject(common_name)

    if not_before is None:
        not_before = datetime.datetime.utcnow()
    if not_after is None:
        not_after = not_before + datetime.timedelta(days=365)
    serial_number = x509.random_serial_number()

    # Generate v1 cert (without extensions) ----------
    cert = x509.CertificateBuilder(
            issuer_name=subject,
            subject_name=subject,
            public_key=private_key.public_key(),
            serial_number=serial_number,
            not_valid_before=not_before,
            not_valid_after=not_after,
    )

    # Add needed extensions --------------------------
    # Basic Constraints
    if ext_basic_constraints is not None:
        cert = add_basic_contraints(cert, ext_basic_constraints)

    # KeyUsage
    if ext_key_usage is not None:
        cert = add_key_usage(cert, ext_key_usage)

    # Key Identifiers
    if ext_key_identifiers:
        cert = add_key_identifiers(cert, private_key)

    # self-sign the cert -----------------------------
    cert = cert.sign(private_key, hashes.SHA256(), default_backend())
    return cert


def gen_soon_to_be_expired_cacert(private_key):
    not_before = datetime.datetime.utcnow() - datetime.timedelta(weeks=1)
    not_after = datetime.datetime.utcnow() + datetime.timedelta(weeks=1)
    return gen_cacert(private_key, not_before=not_before, not_after=not_after)


def gen_expired_cacert(private_key):
    not_before = datetime.datetime.utcnow() - datetime.timedelta(weeks=1)
    not_after = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    return gen_cacert(private_key, not_before=not_before, not_after=not_after)


def gen_not_valid_yet_cacert(private_key):
    not_before = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    return gen_cacert(private_key, not_before=not_before)


def gen_no_basic_constraints_cacert(private_key):
    return gen_cacert(private_key, ext_basic_constraints=None)


def gen_false_basic_constraints_cacert(private_key):
    return gen_cacert(private_key, ext_basic_constraints=False)


def gen_no_key_usage_cacert(private_key):
    return gen_cacert(private_key, ext_key_usage=None)


def gen_false_key_usage_cacert(private_key):
    return gen_cacert(private_key, ext_key_usage=False)


def gen_no_key_identifiers_cacert(private_key):
    return gen_cacert(private_key, ext_key_identifiers=False)


def build_request(renew=False, valid_subject_name=True, valid_hash=True):
    ts = int(time.time())

    device_id = os.urandom(8).hex()
    sid = os.urandom(16).hex()
    nonce = os.urandom(16).hex()
    if renew:
        flags = ("renew",)
    else:
        flags = ()

    to_hash = "{}:{}".format(device_id, nonce)
    hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    signature = hash_digest.hexdigest()

    if valid_subject_name:
        identity = device_id
    else:
        identity = "FakeIdentity"

    csr = gen_csr(identity, valid_hash)

    req = {
            "sn": device_id,
            "ts": ts,
            "sid": sid,
            "auth_type": "dummy",
            "nonce": nonce,
            "signature": signature,
            "csr_str": csr_to_str(csr),
            "flags": flags,
    }

    return req


def cert_from_bytes(cert_bytes):
    return x509.load_pem_x509_certificate(
            data=cert_bytes,
            backend=default_backend()
    )


def get_cert_common_name(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def csr_to_str(csr):
    return str(csr.public_bytes(serialization.Encoding.PEM), encoding='utf-8')


def csr_from_str(csr_str):
    csr_data = bytes(csr_str, encoding='utf-8')
    return x509.load_pem_x509_csr(
            data=csr_data,
            backend=default_backend()
    )
