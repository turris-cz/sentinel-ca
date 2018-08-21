"""
Reusable functions for cryptography stuff
"""

import datetime
import hashlib
import os

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


def gen_key(curve=ECDSA_CURVE):
    return ec.generate_private_key(
            curve=curve,
            backend=default_backend()
    )


def gen_csr(device_id):
    private_key = gen_key()

    subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    csr = x509.CertificateSigningRequestBuilder(subject_name=subject)
    csr = csr.sign(private_key, hashes.SHA256(), default_backend())

    return csr.public_bytes(serialization.Encoding.PEM)


def gen_cacert(private_key, common_name="Fake Sentinel:CA for pytest"):
    subject = build_subject(common_name)

    not_before = datetime.datetime.utcnow()
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
    cert = cert.add_extension(
            x509.BasicConstraints(
                    ca=True,
                    path_length=None
            ),
            critical=True
    )

    # Key Identifiers
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
            ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
    )
    cert = cert.add_extension(ski, critical=False)
    cert = cert.add_extension(aki, critical=False)

    # KeyUsage
    cert = cert.add_extension(
            x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
            ),
            critical=False
    )

    # self-sign the cert -----------------------------
    cert = cert.sign(private_key, hashes.SHA256(), default_backend())
    return cert


def build_good_request():
    device_id = os.urandom(8).hex()
    sid = os.urandom(16).hex()
    nonce = os.urandom(16).hex()
    flags = ()

    to_hash = "{}:{}".format(device_id, nonce)
    hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    digest = hash_digest.hexdigest()

    csr = str(gen_csr(device_id), encoding='utf-8')

    req = {
            "sn": device_id,
            "sid": sid,
            "auth_type": "dummy",
            "nonce": nonce,
            "digest": digest,
            "csr_str": csr,
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


def csr_from_str(csr_str):
    csr_data = bytes(csr_str, encoding='utf-8')
    return x509.load_pem_x509_csr(
            data=csr_data,
            backend=default_backend()
    )
