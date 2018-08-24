"""
Reusable sn-related functions
"""

import sn


def build_checker_reply(status="ok", message="", msg_type="sentinel/certificator/checker"):
    # add status and message to the payload if they are not None
    msg_payload = {}
    if status is not None:
        msg_payload["status"] = status
    if message is not None:
        msg_payload["message"] = message

    return sn.encode_msg(msg_type, msg_payload)


def checker_good_reply():
    return build_checker_reply()


def checker_fail_reply():
    return build_checker_reply("fail", "Auth error happened")


def checker_error_reply():
    return build_checker_reply("error", "Checker error")


def checker_bad_reply1():
    return build_checker_reply(None, "Interface malformed: Status is missing")


def checker_bad_reply2():
    return build_checker_reply(
            "ok",
            "Interface malformed: Wrong message type",
            "sentinel/certificator/foo"
    )
