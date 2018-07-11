"""
Redis wrappers for Sentinel:CA
"""

import json
import logging
import redis

# to setup logger handlers
import sn

from .crypto import get_cert_bytes
from .exceptions import CAParseError

logger = logging.getLogger("ca")


KEY_TTL = 2*60
STATUS_KEYSPACE = "auth_state"
CERT_KEYSPACE = "certificate"

QUEUE_NAME = "csr"
REQUIRED_REQUEST_KEYS = [
    "sn",
    "sid",
    "auth_type",
    "nonce",
    "digest",
    "csr_str",
]


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


def get_redis_item(r, queue, timeout=0):
    try:
        return r.brpop(queue, timeout)[1]
    except TypeError as e:
        # when brpop returns None
        logger.exception(e)
        raise CAParseError("No redis item received")


def redis_item_to_dict(item):
    try:
        return json.loads(str(item, encoding='utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        # when item is not a UTF-8 json
        logger.exception(e)
        raise CAParseError("Invalid request format")


def redis_cert_key(request):
    return "{}:{}:{}".format(CERT_KEYSPACE, request["sn"], request["sid"])


def check_request(request):
    for key in REQUIRED_REQUEST_KEYS:
        if key not in request:
            raise CAParseError("'{}' is missing in the request".format(key))


def get_request(r):
    item = get_redis_item(r, QUEUE_NAME)
    request = redis_item_to_dict(item)
    logger.debug("REDIS brpop %s: %s", QUEUE_NAME, request)
    return request


def build_reply(cert):
    return {
        "cert": str(get_cert_bytes(cert), encoding='utf-8'),
        "message": "",
    }


def build_error(message):
    return {
        "cert": "",
        "message": message,
    }


def send_reply(r, key, reply):
    logger.debug("REDIS set %s: %s", key, reply)
    r.set(key, json.dumps(reply), ex=KEY_TTL)
