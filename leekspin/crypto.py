# -*- coding: utf-8 -*-

"""rsa ― OpenSSL RSA key and certificate utilities, fingerprint representation
conversions, and other cryptographic utilities related to Onion Relay RSA
keys.

**Module Overview:**

Exceptions:
```````````
::

  OpenSSLKeyGenError - Raised if there is an OpenSSL error during key creation.

Functions:
``````````
::

  convertToSpaceyFingerprint - Add space character delimiters to a fingerprint.

"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals


class InvalidFingerprint(ValueError):
    """Raised when a key fingerprint is invalid."""


def convertToSpaceyFingerprint(fingerprint):
    """Convert to a space-delimited 40 character fingerprint

    Given a 40 character string, usually the the SHA-1 hash of the
    DER encoding of an ASN.1 RSA public key, such as:
      |
      | 72C2F0AE1C14F40ED37ED5F5434B64711A658E46
      |

    convert it to the following format:
      |
      | 72C2 F0AE 1C14 F40E D37E D5F5 434B 6471 1A65 8E46
      |

    :param string fingerprint: A 40 character hex fingerprint.
    :rtype: string
    :raises InvalidFingerprint: If the fingerprint isn't 40 bytes in length.
    :returns: A 4-character space-delimited fingerprint.
    """
    if len(fingerprint) != 40:
        raise InvalidFingerprint("Invalid fingerprint (< 40 bytes): %r"
                                 % fingerprint)
    return " ".join([fingerprint[i:i+4] for i in xrange(0, 40, 4)])
