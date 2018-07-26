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

SLEEP_MIN = 3
SLEEP_MAX = 21

RSA_BITS = 4096
RSA_EXPONENT = 0x10001 # 65537
ECDSA_CURVE = ec.SECP256R1()

AUTH_TYPE = "atsha"
QUEUE_NAME = "csr"
CERT_KEYSPACE = "certificate"
AUTH_KEYSPACE = "auth_state"

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


def redis_item_to_dict(item):
    try:
        return json.loads(str(item, encoding='utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def log_message(message, direction="none", extra_line=False):
    symbol = LOG_MESSAGE_MAPPER[direction]
    print("{} {}".format(symbol, message))
    if extra_line:
        print("")


def print_redis_list(r):
    llen = r.llen(QUEUE_NAME)
    i = llen
    for item in r.lrange(QUEUE_NAME, 0, -1):
        print("{}: {}".format(i-1, redis_item_to_dict(item)))
        i-=1
    print("# of items in queue: {}".format(llen))
    print("")


def print_redis_certs(r):
    i = 0
    for key in r.scan_iter(match="{}:*".format(CERT_KEYSPACE)):
        ttl = r.ttl(key)
        print("{:4d}: {}".format(ttl, str(key, encoding='utf-8')))
        i += 1
    print("# of certificates: {}".format(i))
    print("")


def print_redis_auth(r):
    i = 0
    for key in r.scan_iter(match="{}:*".format(AUTH_KEYSPACE)):
        auth = r.get(key)
        ttl = r.ttl(key)
        print("{:4d}: {} {}".format(ttl, str(key, encoding='utf-8'), redis_item_to_dict(auth)))
        i += 1
    print("# of auth states: {}".format(i))
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


def gen_csr(device_id):
    if random.choice((True, True, False)):
        # 1 of 4 keys would be a RSA
        key_type = random.choice(("ecdsa", "ecdsa", "ecdsa", "rsa"))
        private_key = gen_key(key_type)
    else:
        private_key = GLOBAL_KEY

    subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    csr = x509.CertificateSigningRequestBuilder(subject_name=subject)
    csr = csr.sign(private_key, hashes.SHA256(), default_backend())

    return csr.public_bytes(serialization.Encoding.PEM)


def build_request():
    if random.choice((True, True, False)):
        device_id = secrets.token_hex(8)
    else:
        device_id = "0042dead99beef11"

    sid = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    to_hash = "{}:{}".format(device_id, nonce)

    if random.choice((True, True, False)):
        hash_digest = hashlib.sha256(bytes(to_hash, encoding='utf-8'))
    else:
        hash_digest = hashlib.sha1(bytes(to_hash, encoding='utf-8'))
    digest = hash_digest.hexdigest()

    if random.choice((True, True, False)):
        subject = device_id
    else:
        subject = secrets.token_hex(8)

    if random.choice((True, False)):
        flags = ("renew",)
    else:
        flags = ()

    csr = str(gen_csr(subject), encoding='utf-8')

    request = {
            "sn": device_id,
            "sid": sid,
            "auth_type": AUTH_TYPE,
            "nonce": nonce,
            "digest": digest,
            "csr_str": csr,
            "flags": flags,
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
            time.sleep(1)
            print_redis_auth(r)

        time.sleep(random.randint(SLEEP_MIN, SLEEP_MAX))


# one common key for testing repetive queries
GLOBAL_KEY = gen_key()


if __name__ == "__main__":
    main()
