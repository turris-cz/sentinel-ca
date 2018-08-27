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
