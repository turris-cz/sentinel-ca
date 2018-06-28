#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import sys
import datetime
import configparser
import json

import redis
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


def log_message(msg_type, message, direction="none", extra_line=False):
    symbol = LOG_MESSAGE_MAPPER[direction]
    print("{} {}: {}".format(symbol, msg_type, message))
    if extra_line:
        print("")


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
    parser.add_argument(
            "-l", "--log-messages",
            action='store_true',
            help="Log incoming/outgoing messages"
    )
    return parser


def prepare_config():
    conf = configparser.ConfigParser()

    conf.add_section("redis")
    conf.set("redis", "socket", "")
    conf.set("redis", "host", "127.0.0.1")
    conf.set("redis", "port", "6379")
    conf.set("redis", "password", "")

    return conf


def config(config_path):
    conf = prepare_config()
    res = conf.read(config_path)
    if config_path not in res:
        raise FileNotFoundError()

    return conf


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
        csr_data = bytes(csr_str, encoding='utf-8')
        csr = x509.load_pem_x509_csr(
                data=csr_data,
                backend=default_backend()
        )
    except (UnicodeEncodeError, ValueError) as e:
        raise CAError(str(e))

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

def build_aki(cert):
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)

    except x509.ExtensionNotFound:
        public_key = cert.public_key()
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)

    return aki

def build_client_cert(csr, subject, issuer, aki, serial_number=None, days=CERT_DAYS):
    # generate missing and optional parameters -------
    not_before = datetime.datetime.utcnow()
    not_after = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    if not serial_number:
        serial_number = x509.random_serial_number()

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


def sign_csr(ca_key, ca_cert, csr, identity):
    cert = build_client_cert(
            csr=csr,
            subject=build_subject(identity),
            issuer=ca_cert.subject,
            aki=build_aki(ca_cert),
    )

    cert = cert.sign(ca_key, SIGNING_HASH, default_backend())

    return cert


def issue_cert(ca_key, ca_cert, request):
    device_id = request["sn"]
    csr = load_csr(request["csr_str"])

    check_csr(csr, device_id)
    cert = sign_csr(ca_key, ca_cert, csr, device_id)

    return cert.public_bytes(serialization.Encoding.PEM)


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


def build_reply(cert_bytes=b'', message=""):
    cert_str = str(cert_bytes, encoding='utf-8')

    return {
        "cert": cert_str,
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
def check_auth(socket, request, log_messages):
    auth_request = {key:request[key] for key in AUTH_REQUEST_KEYS}
    socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, auth_request))
    if log_messages:
        log_message(MESSAGE_TYPE, auth_request, direction="out")

    zmq_reply = socket.recv_multipart()
    msg_type, auth_reply = sn.parse_msg(zmq_reply)
    if log_messages:
        log_message(msg_type, auth_reply, direction="in")

    check_auth_reply(msg_type, auth_reply)
    if auth_reply["status"] != "ok":
        raise CAError(auth_reply["message"])


def get_request(r, queue, timeout=0):
    item = r.brpop(queue, timeout)
    request = redis_item_to_dict(item[1])
    return request


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

    while True:
        request = get_request(r, queue=QUEUE_NAME)
        if ctx.args.log_messages:
            log_message(QUEUE_NAME, request, direction="in")

        try:
            check_request(request)
            check_auth(socket, request, ctx.args.log_messages)
            cert = issue_cert(ca_key, ca_cert, request)
            reply = build_reply(cert_bytes=cert)
        except CAError as e:
            reply = build_reply(message=str(e))

        redis_key = redis_cert_key(request)
        if ctx.args.log_messages:
            log_message(redis_key, reply, direction="out", extra_line=True)
        r.set(redis_key, json.dumps(reply), ex=KEY_TTL)


if __name__ == "__main__":
    main()
