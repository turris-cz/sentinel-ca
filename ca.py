#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import sys
import datetime
import configparser
import json
import logging

import redis
import sqlite3
import zmq
import sn

# backend
from cryptography.hazmat.backends import default_backend
# serialization
from cryptography.hazmat.primitives import serialization
# signing certs
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("ca")

CONFIG_DEFAULT_PATH = "ca.ini"

STATUS_KEYSPACE = "auth_state"
CERT_KEYSPACE = "certificate"
KEY_TTL = 2*60 # 2 m

QUEUE_NAME = "csr"
REQUIRED_REQUEST_KEYS = [
    "sn",
    "sid",
    "auth_type",
    "nonce",
    "digest",
    "csr_str",
]

MESSAGE_TYPE = "sentinel/certificator/checker"
AUTH_REQUEST_KEYS = [
    "sn",
    "auth_type",
    "nonce",
    "digest",
]

REQUIRED_AUTH_REPLY_KEYS = [
    "status",
    "message",
]

LOG_MESSAGE_MAPPER = {
    "in": "←",
    "out": "→",
    "none": " ",
}

SIGNING_HASH = hashes.SHA256()
ALLOWED_HASHES = {
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
}
CERT_DAYS = 30


class CAError(Exception):
    pass




def get_argparser(parser):
    parser.add_argument(
            "-C", "--ca-cert",
            required=True,
            metavar="CERT",
            help="Certificate of the CA"
    )
    parser.add_argument(
            "-K", "--ca-key",
            required=True,
            metavar="KEY",
            help="Private key of the CA"
    )
    parser.add_argument(
            "-F", "--ca-ignore-errors",
            action='store_true',
            help="Ignore cert and/or key checks errors"
    )
    parser.add_argument(
            "-c", "--config",
            required=True,
            default=CONFIG_DEFAULT_PATH,
            metavar="CONF",
            help="Path to configuration file"
    )

    return parser


def prepare_config():
    conf = configparser.ConfigParser()

    conf.add_section("redis")
    conf.set("redis", "socket", "")
    conf.set("redis", "host", "127.0.0.1")
    conf.set("redis", "port", "6379")
    conf.set("redis", "password", "")

    conf.add_section("db")
    conf.set("db", "path", "ca.db")

    return conf


def config(config_path):
    conf = prepare_config()
    res = conf.read(config_path)
    if config_path not in res:
        raise FileNotFoundError()

    return conf


def get_cert_common_name(cert):
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        # catch all Exceptions as the x509 certificate interface is not so clean
        logger.exception("Common name is not present")
        common_name = "N/A"

    return common_name


def check_cert_private_key_match(cert, key):
    cert_key = cert.public_key()
    public_key = key.public_key()

    if public_key.public_numbers() != cert_key.public_numbers():
        raise CAError("Private key does not match with certificate public key")

def check_cert_valid_dates(cert):
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        raise CAError("Certificate is not valid yet")

    if cert.not_valid_after < now:
        raise CAError("Certificate is expired")

def check_cert_basic_constraints(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise CAError("Certificate does not have Basic Constraints extension")

    if not ext.value.ca:
        raise CAError("Certificate is not a CA cert")

def check_cert_key_usage(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        raise CAError("Certificate does not have Key Usage extension")

    if not ext.value.key_cert_sign:
        raise CAError("CA key usage does not allow cert signing")

def check_cert_subject_key_identifier(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        raise CAError("Certificate does not have Subject Key Identifier extension")

def check_cert(cert, key, ignore_errors):
    try:
        check_cert_private_key_match(cert, key)
        check_cert_basic_constraints(cert)
        check_cert_key_usage(cert)
        check_cert_subject_key_identifier(cert)
        check_cert_valid_dates(cert)

    except CAError as e:
        print(str(e), file=sys.stderr)
        if not ignore_errors:
            sys.exit(2)


def load_csr(csr_str):
    try:
        # construct x509 request from PEM string
        csr_data = bytes(csr_str, encoding='utf-8')
        csr = x509.load_pem_x509_csr(
                data=csr_data,
                backend=default_backend()
        )
    except (UnicodeEncodeError, ValueError):
        raise CAError("Invalid CSR format")

    return csr


def check_csr_common_name(csr, identity):
    common_names = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise CAError("CSR has not exactly one CommonName")

    common_name = common_names[0].value
    if common_name != identity:
        raise CAError("CSR CommonName ({}) does not match desired identity".format(common_name))

def check_csr_hash(csr):
    h = csr.signature_hash_algorithm
    if type(h) not in ALLOWED_HASHES:
        raise CAError("CSR is signed with not allowed hash ({})".format(h.name))

def check_csr_signature(csr):
    if not csr.is_signature_valid:
        raise CAError("Request signature is not valid")

def check_csr(csr, device_id):
    check_csr_common_name(csr, device_id)
    check_csr_hash(csr)
    check_csr_signature(csr)


def build_subject(identity):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, identity),
    ])

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


def init_db(conf):
    conn = sqlite3.connect(conf.get("db", "path"))

    try:
        # test table and columns existence
        c = conn.cursor()
        c.execute("""
            SELECT sn, state, common_name, not_before, not_after, cert
              FROM certs
              LIMIT 1
        """)
        c.close()
    except sqlite3.OperationalError:
        raise CAError("Incorrect DB scheme")

    return conn


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

    raise CAError("Could not get unique certificate s/n")


def store_cert(db, cert):
    serial_number = cert.serial_number
    identity = get_cert_common_name(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    c = db.cursor()
    c.execute("""
            INSERT INTO certs(sn, state, common_name, not_before, not_after, cert)
            VALUES (?,?,?,?,?,?)
            """,
            (str(serial_number), "valid", identity, not_before, not_after, cert_bytes)
    )
    c.close()
    db.commit()


def init_redis(conf):
    redis_socket = None
    if conf.get("redis", "socket"):
        redis_socket = conf.get("redis", "socket")

    return redis.StrictRedis(
            host=conf.get("redis", "host"),
            port=conf.getint("redis", "port"),
            password=conf.get("redis", "password"),
            unix_socket_path=redis_socket
    )


def redis_item_to_dict(item):
    return json.loads(str(item, encoding='utf-8'))


def redis_cert_key(request):
    return "{}:{}:{}".format(CERT_KEYSPACE, request["sn"], request["sid"])


def build_reply(cert):
    cert_str = str(
        cert.public_bytes(serialization.Encoding.PEM),
        encoding='utf-8'
    )

    return {
        "cert": cert_str,
        "message": "",
    }

def build_error(message):
    return {
        "cert": "",
        "message": message,
    }


def check_request(message):
    # check presence of needed keys
    for key in REQUIRED_REQUEST_KEYS:
        if key not in message:
            raise CAError("'{}' is missing in the request".format(key))


def check_auth_reply(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CAError("Unknown message type in auth reply '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_AUTH_REPLY_KEYS:
        if key not in message:
            raise CAError("'{}' is missing in the auth reply".format(key))


"""checker via zmq"""
def check_auth(socket, request):
    auth_request = {key:request[key] for key in AUTH_REQUEST_KEYS}
    socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, auth_request))
    logger.debug("%s %s: %s", LOG_MESSAGE_MAPPER["out"], MESSAGE_TYPE, auth_request)

    zmq_reply = socket.recv_multipart()
    msg_type, auth_reply = sn.parse_msg(zmq_reply)
    logger.debug("%s %s: %s", LOG_MESSAGE_MAPPER["in"], msg_type, auth_reply)

    check_auth_reply(msg_type, auth_reply)
    if auth_reply["status"] != "ok":
        raise CAError(auth_reply["message"])


def get_request(r, queue, timeout=0):
    item = r.brpop(queue, timeout)
    request = redis_item_to_dict(item[1])
    return request


def send_reply(r, key, reply):
    r.set(key, json.dumps(reply), ex=KEY_TTL)


def main():
    ctx = sn.SN(zmq.Context.instance(), get_argparser(sn.get_arg_parser()))
    socket = ctx.get_socket(("checker", "REQ"))

    ca_cert, ca_key = init_ca(
            ctx.args.ca_cert,
            ctx.args.ca_key,
            ignore_errors=ctx.args.ca_ignore_errors
    )

    conf = config(ctx.args.config)
    r = init_redis(conf)
    db = init_db(conf)

    while True:
        try:
            request = get_request(r, queue=QUEUE_NAME)
            logger.debug("%s %s: %s", LOG_MESSAGE_MAPPER["in"], QUEUE_NAME, request)

            check_request(request)
            check_auth(socket, request)
            cert = issue_cert(db, ca_key, ca_cert, request)
            store_cert(db, cert)

            logger.info("Certificate with s/n %d for %s was issued", cert.serial_number, get_cert_common_name(cert))
            reply = build_reply(cert)
        except CAError as e:
            logger.error("Invalid request: %s", str(e))
            reply = build_error(str(e))

        redis_key = redis_cert_key(request)
        logger.debug("%s %s: %s", LOG_MESSAGE_MAPPER["out"], redis_key, reply)
        send_reply(r, redis_key, reply)


if __name__ == "__main__":
    main()
