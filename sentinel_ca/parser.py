"""
arguments and config parser for Sentinel:CA
"""

import configparser

CONFIG_DEFAULT_PATH = "ca.ini"


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
