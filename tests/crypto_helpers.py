"""
Reusable functions for cryptography stuff
"""

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


def pregen_key():
    return """-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAsigTYpUhxkr8higCIt0P1eWJvza1l6uYYrxSSSmTJXAMzZtY/o5L/
lfzrVHhArG2gBwYFK4EEACKhZANiAAR5rbD/kssgpNqd2RfzfTdsVd9fTPxn5cyG
1YJI/skQNjN6JtWs+iloO1ai9LwG6443n8yufyg4B4l49+f8hbw3C40OVYCnc+yO
hIgjbGNKZKpALteO4xcEUYO8AuB8p24=
-----END EC PRIVATE KEY-----
"""


def pregen_cert():
    return """-----BEGIN CERTIFICATE-----
MIICWTCCAd6gAwIBAgIJAL9+VgWrARQwMAoGCCqGSM49BAMCMGIxCzAJBgNVBAYT
AkNaMQ8wDQYDVQQHDAZQcmFndWUxGTAXBgNVBAoMEENaLk5JQywgei5zLnAuby4x
DzANBgNVBAsMBlR1cnJpczEWMBQGA1UEAwwNVGVzdGluZyBDQSBYNDAeFw0xODA4
MTYxNDQyMjVaFw0xOTAxMTMxNDQyMjVaMGIxCzAJBgNVBAYTAkNaMQ8wDQYDVQQH
DAZQcmFndWUxGTAXBgNVBAoMEENaLk5JQywgei5zLnAuby4xDzANBgNVBAsMBlR1
cnJpczEWMBQGA1UEAwwNVGVzdGluZyBDQSBYNDB2MBAGByqGSM49AgEGBSuBBAAi
A2IABHmtsP+SyyCk2p3ZF/N9N2xV319M/GflzIbVgkj+yRA2M3om1az6KWg7VqL0
vAbrjjefzK5/KDgHiXj35/yFvDcLjQ5VgKdz7I6EiCNsY0pkqkAu147jFwRRg7wC
4HynbqNgMF4wHQYDVR0OBBYEFCNJiZ1Z59QYU0pMID2bOV5p+t+CMB8GA1UdIwQY
MBaAFCNJiZ1Z59QYU0pMID2bOV5p+t+CMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0P
BAQDAgEGMAoGCCqGSM49BAMCA2kAMGYCMQCeFTAmUmzlCFZKHAlfFaDNIYGA77M1
wCJNow21oMdeQ7iuz3Fqo+p645VoVhehmF4CMQCgArqUfn2afCVq6jxSuxbiCh2n
RVNZSm/Vu9R7RZzg6VpRiIyshXT+DN1NzVbK8R4=
-----END CERTIFICATE-----
"""


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
