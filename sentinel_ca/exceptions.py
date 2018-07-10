"""
Sentinel:CA Exceptions
"""

class CAError(Exception):
    pass

class CASetupError(CAError):
    pass

class CAParseError(CAError):
    pass

class CARequestError(CAError):
    pass
