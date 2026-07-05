"""
DomainSpyder -- Domain Intelligence Framework
"""

import warnings

# Suppress urllib3's NotOpenSSLWarning on systems where Python is linked
# against LibreSSL (e.g. macOS system Python 3.9). Must run before urllib3
# is imported by requests/httpx, so it lives here at package import time.
warnings.filterwarnings(
    "ignore",
    message=r"urllib3 v2 only supports OpenSSL 1.1.1\+.*",
)

from domainspyder.config import VERSION

__version__ = VERSION
