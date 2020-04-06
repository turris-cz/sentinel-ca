"""
Sentinel Network with arguments and config parser for Sentinel:CA
"""

from errno import ENOENT
import configparser
import logging
import os

import zmq

import sn

from .exceptions import CAParseError, CARequestClientError, CARequestServerError

logger = logging.getLogger("ca")


CONFIG_DEFAULT_PATH = "ca.ini"
VALID_DAYS_DEFAULT = "60"
VALID_DAYS_MIN_DEFAULT = "15"

MESSAGE_TYPE = "sentinel/certificator/checker"
AUTH_REQUEST_KEYS = (
    "sn",
    "auth_type",
    "nonce",
    "signature",
)
REQUIRED_AUTH_REPLY_KEYS = (
    "status",
    "message",
)


def init_sn():
    ctx = sn.SN(
            zmq.Context.instance(),
            get_argparser(sn.get_arg_parser())
    )
    socket = ctx.get_socket(("checker", "REQ"))

    return ctx, socket


def get_argparser(parser):
    parser.add_argument(
            "-c", "--config",
            required=True,
            default=CONFIG_DEFAULT_PATH,
            metavar="CONF",
            help="Path to configuration file"
    )
    parser.add_argument(
            "-F", "--ca-ignore-errors",
            action='store_true',
            help="Ignore cert and/or key checks errors"
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

    conf.add_section("ca")
    conf.set("ca", "cert", "")
    conf.set("ca", "key", "")
    conf.set("ca", "password", "")
    conf.set("ca", "valid_days", VALID_DAYS_DEFAULT)
    conf.set("ca", "valid_days_min", VALID_DAYS_MIN_DEFAULT)

    return conf


def config(config_path):
    conf = prepare_config()
    res = conf.read(config_path)
    if config_path not in res:
        raise FileNotFoundError(ENOENT, os.strerror(ENOENT), config_path)

    return conf


def check_auth_reply(msg_type, message):
    # check message type
    if msg_type != MESSAGE_TYPE:
        raise CARequestServerError("Unknown message type in auth reply '{}'".format(msg_type))

    # check presence of needed keys
    for key in REQUIRED_AUTH_REPLY_KEYS:
        if key not in message:
            raise CARequestServerError("'{}' is missing in the auth reply".format(key))


def check_auth(socket, request):
    auth_request = {key:request[key] for key in AUTH_REQUEST_KEYS}
    socket.send_multipart(sn.encode_msg(MESSAGE_TYPE, auth_request))
    logger.debug("ZMQ send %s: %s", MESSAGE_TYPE, auth_request)

    zmq_reply = socket.recv_multipart()
    msg_type, auth_reply = sn.parse_msg(zmq_reply)
    logger.debug("ZMQ recv %s: %s", msg_type, auth_reply)

    check_auth_reply(msg_type, auth_reply)
    # distinguish fail and other not-ok state
    if auth_reply["status"] == "fail":
        raise CARequestClientError(auth_reply["message"])
    if auth_reply["status"] != "ok":
        raise CARequestServerError(auth_reply["message"])
