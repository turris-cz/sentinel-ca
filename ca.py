#!/usr/bin/env python3
## ca.py
#
# Sentinel:CA: a certificator component

import hashlib
import configparser
import json

import redis
import zmq
import sn


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


class CAError(Exception):
    pass


def log_message(msg_type, message, direction="none", extra_line=False):
    symbol = LOG_MESSAGE_MAPPER[direction]
    print("{} {}: {}".format(symbol, msg_type, message))
    if extra_line:
        print("")


def get_argparser(parser):
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
    return json.loads(str(item, encoding='utf-8'))


def redis_cert_key(request):
    return "{}:{}:{}".format(CERT_KEYSPACE, request["sn"], request["sid"])


def issue_cert(sn):
    hash_digest = hashlib.sha256(bytes(sn, encoding='utf-8'))
    return hash_digest.hexdigest()


def build_reply(sn, message=""):
    if sn:
        cert = issue_cert(sn)
        reply = {
                "cert": cert,
                "message": message,
        }

    else:
        reply = {
                "cert": "",
                "message": message,
        }

    return reply


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


def process_request(socket, request, log_messages):
    try:
        check_request(request)
        check_auth(socket, request, log_messages)
        return build_reply(request["sn"])
    except CAError as e:
        return build_reply("", str(e))


def get_request(r, queue, timeout=0):
    item = r.brpop(queue, timeout)
    request = redis_item_to_dict(item[1])
    return request


def main():
    ctx = sn.SN(zmq.Context.instance(), get_argparser(sn.get_arg_parser()))
    socket = ctx.get_socket(("checker", "REQ"))

    conf = config(ctx.args.config)
    r = init_redis(conf)

    while True:
        request = get_request(r, queue=QUEUE_NAME)
        if ctx.args.log_messages:
            log_message(QUEUE_NAME, request, direction="in")

        reply = process_request(socket, request, ctx.args.log_messages)

        redis_key = redis_cert_key(request)
        if ctx.args.log_messages:
            log_message(redis_key, reply, direction="out", extra_line=True)
        r.set(redis_key, json.dumps(reply), ex=KEY_TTL)


if __name__ == "__main__":
    main()
