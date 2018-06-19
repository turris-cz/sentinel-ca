#!/usr/bin/env python3
## checker.py
#
# dummy implementation of cert-api: a certificator component

import argparse
import configparser
import hashlib
import secrets
import random
import json
import time

import redis

# backend
from cryptography.hazmat.backends import default_backend
# serialization
from cryptography.hazmat.primitives import serialization
# private/public keys
from cryptography.hazmat.primitives.asymmetric import ec, rsa
# request
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


CONFIG_DEFAULT_PATH = "cert-api.ini"

SLEEP_MIN = 7
SLEEP_MAX = 42

RSA_BITS = 4096
RSA_EXPONENT = 0x10001 # 65537
ECDSA_CURVE = ec.SECP256R1()

AUTH_TYPE = "atsha"
QUEUE_NAME = "csr"
CERT_KEYSPACE = "certificate"

LOG_MESSAGE_MAPPER = {
    "incoming": "←",
    "outgoing": "→",
    "none": " ",
}


class CertApiError(Exception):
    pass


def get_arg_parser():
    parser = argparse.ArgumentParser()
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


def redis_item_to_json(item):
    return str(item, encoding='utf-8').replace("'", '"')


def log_message(message, direction="none", extra_line=False):
    symbol = LOG_MESSAGE_MAPPER[direction]
    print("{} {}".format(symbol, message))
    if extra_line:
        print("")


def print_redis_list(r):
    i = r.llen(QUEUE_NAME)
    if i:
        for item in r.lrange(QUEUE_NAME, 0, -1):
            print("{}: {}".format(i-1, redis_item_to_json(item)))
            i-=1
    else:
        print("∅: <Empty queue>")
    print("")


def print_redis_certs(r):
    i = 0
    for key in r.scan_iter(match="{}:*".format(CERT_KEYSPACE)):
        ttl = r.ttl(key)
        print("{:3d}: {}".format(ttl, str(key, encoding='utf-8')))
        i += 1
    print("# of certificates: {}".format(i))
    print("")


def gen_key(key_type="ecdsa", curve=ECDSA_CURVE, rsa_bits=RSA_BITS, rsa_exponent=RSA_EXPONENT):
    if key_type == "ecdsa":
        private_key = ec.generate_private_key(
                curve=curve,
                backend=default_backend()
        )
    elif key_type == "rsa":
        private_key = rsa.generate_private_key(
                public_exponent=RSA_EXPONENT,
                key_size=RSA_BITS,
                backend=default_backend()
        )
    else:
        raise CertApiError("Unsupported key type: {}".key_type)

    return private_key


def gen_csr(sn):
    # 1 of 4 keys would be a RSA
    key_type = random.choice(("ecdsa", "ecdsa", "ecdsa", "rsa"))
    private_key = gen_key(key_type)

    subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, sn),
    ])
    csr = x509.CertificateSigningRequestBuilder(subject_name=subject)
    csr = csr.sign(private_key, hashes.SHA256(), default_backend())

    return csr.public_bytes(serialization.Encoding.PEM)


def build_request():
    sn = secrets.token_hex(8)
    sid = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    to_hash = "{}:{}".format(sn, nonce)

    if random.choice((True, False)):
        hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    else:
        hash_digest = hashlib.sha1(bytes(to_hash, encoding='utf-8'))
    digest = hash_digest.hexdigest()

    csr = str(gen_csr(sn), encoding='utf-8')

    request = {
            "sn": sn,
            "sid": sid,
            "auth_type": AUTH_TYPE,
            "nonce": nonce,
            "digest": digest,
            "csr_str": csr,
    }

    return request


def main():
    args = get_arg_parser().parse_args()
    conf = config(args.config)

    r = init_redis(conf)

    while True:
        request = build_request()
        if args.log_messages:
            log_message(request, direction="outgoing", extra_line=True)

        r.lpush(QUEUE_NAME, json.dumps(request))

        if args.log_messages:
            time.sleep(1)
            print_redis_list(r)
            time.sleep(1)
            print_redis_certs(r)

        time.sleep(random.randint(SLEEP_MIN, SLEEP_MAX))


if __name__ == "__main__":
    main()
