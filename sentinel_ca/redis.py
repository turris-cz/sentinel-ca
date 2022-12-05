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


CERT_TTL = 30*60
AUTH_TTL = 5*60

QUEUE_NAME = "csr"
REQUIRED_REQUEST_KEYS = [
    "sn",
    "ts",
    "sid",
    "auth_type",
    "nonce",
    "signature",
    "csr_str",
    "flags",
]


def init_redis(conf):
    redis_socket = None
    if conf.get("redis", "socket"):
        redis_socket = conf.get("redis", "socket")

    return redis.StrictRedis(
            host=conf.get("redis", "host"),
            port=conf.getint("redis", "port"),
            username=conf.get("redis", "username"),
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
        d = json.loads(str(item, encoding='utf-8'))
        if d is None:
            raise CAParseError("Empty request")

    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        # when item is not a UTF-8 json
        logger.exception(e)
        raise CAParseError("Invalid request format")

    return d


def auth_key(device_id, sid):
    return "auth_state:{}:{}".format(device_id, sid)


def cert_key(device_id):
    return "certificate:{}".format(device_id)


def check_request(request):
    for key in REQUIRED_REQUEST_KEYS:
        if key not in request:
            raise CAParseError("'{}' is missing in the request".format(key))


def get_request(r, queue_name=QUEUE_NAME):
    item = get_redis_item(r, queue_name)
    request = redis_item_to_dict(item)
    logger.debug("REDIS brpop %s: %s", QUEUE_NAME, request)
    return request


def set_auth(r, device_id, sid, status, message):
    key = auth_key(device_id, sid)
    auth = {
            "status": status,
            "message": message,
    }
    logger.debug("REDIS set %s: %s", key, auth)
    r.set(key, json.dumps(auth), ex=AUTH_TTL)


def set_auth_ok(r, device_id, sid, message=""):
    set_auth(r, device_id, sid, "ok", message)


def set_auth_fail(r, device_id, sid, message=""):
    set_auth(r, device_id, sid, "fail", message)


def set_auth_error(r, device_id, sid, message=""):
    set_auth(r, device_id, sid, "error", message)


def set_cert(r, device_id, cert):
    key = cert_key(device_id)
    cert_bytes = get_cert_bytes(cert)
    logger.debug("REDIS set %s: %s", key, cert_bytes)
    r.set(key, cert_bytes, ex=CERT_TTL)
