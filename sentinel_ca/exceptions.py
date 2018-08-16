"""
Sentinel:CA Exceptions
"""

class CAError(Exception):
    pass

class CASetupError(CAError):
    pass

class CAParseError(CAError):
    pass

class CARequestClientError(CAError):
    pass

class CARequestServerError(CAError):
    pass
