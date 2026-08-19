from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No Check Point credentials. Send the X-CheckPoint-Client-Id, "
    "X-CheckPoint-Access-Key, and X-CheckPoint-Region headers.",
    False,
)
