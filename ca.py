#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import json
import logging

import redis
import sqlite3
import zmq
import sn

import sentinel_ca


logger = logging.getLogger("ca")

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
        raise CASetupError("Incorrect DB scheme")

    return conn


def store_cert(db, cert):
    serial_number = cert.serial_number
    identity = sentinel_ca.get_cert_common_name(cert)
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


def build_reply(cert):
    cert_str = str(
        sentinel_ca.get_cert_bytes(cert),
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
            raise CAParseError("'{}' is missing in the request".format(key))


def check_auth_reply(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CARequestError("Unknown message type in auth reply '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_AUTH_REPLY_KEYS:
        if key not in message:
            raise CARequestError("'{}' is missing in the auth reply".format(key))


"""checker via zmq"""
def check_auth(socket, request):
    auth_request = {key:request[key] for key in AUTH_REQUEST_KEYS}
    socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, auth_request))
    logger.debug("ZMQ send %s: %s", MESSAGE_TYPE, auth_request)

    zmq_reply = socket.recv_multipart()
    msg_type, auth_reply = sn.parse_msg(zmq_reply)
    logger.debug("ZMQ recv %s: %s", msg_type, auth_reply)

    check_auth_reply(msg_type, auth_reply)
    if auth_reply["status"] != "ok":
        raise CARequestError(auth_reply["message"])


def get_request(r, queue):
    item = get_redis_item(r, queue)
    request = redis_item_to_dict(item)
    logger.debug("REDIS brpop %s: %s", queue, request)
    return request


def send_reply(r, key, reply):
    logger.debug("REDIS set %s: %s", key, reply)
    r.set(key, json.dumps(reply), ex=KEY_TTL)


def process(r, socket, db, ca_key, ca_cert):
    try:
        request = get_request(r, queue=QUEUE_NAME)
        check_request(request)
    except CAParseError as e:
        logger.error("Malformed request: %s", str(e))
        return

    try:
        check_auth(socket, request)
        cert = sentinel_ca.issue_cert(db, ca_key, ca_cert, request)
        store_cert(db, cert)

        logger.info(
                "Certificate with s/n %d for %s was issued",
                cert.serial_number,
                sentinel_ca.get_cert_common_name(cert)
        )
        reply = build_reply(cert)
    except CARequestError as e:
        logger.error("Invalid request: %s", str(e))
        reply = build_error(str(e))

    redis_key = redis_cert_key(request)
    send_reply(r, redis_key, reply)


def main():
    ctx = sn.SN(
            zmq.Context.instance(),
            sentinel_ca.get_argparser(sn.get_arg_parser())
    )
    socket = ctx.get_socket(("checker", "REQ"))

    ca_cert, ca_key = sentinel_ca.init_ca(
            ctx.args.ca_cert,
            ctx.args.ca_key,
            ignore_errors=ctx.args.ca_ignore_errors
    )

    conf = sentinel_ca.config(ctx.args.config)
    r = init_redis(conf)
    db = init_db(conf)

    while True:
        process(r, socket, db, ca_key, ca_cert)


if __name__ == "__main__":
    main()
