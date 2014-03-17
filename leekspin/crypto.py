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

import binascii

from leekspin import const
from leekspin import rsa
from leekspin import tls


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

def makeOnionKeys(bridge=True, digest='sha1'):
    """Make all the keys and certificates necessary to fake an OR.

    The encodings for the various key and descriptor digests needed are
    described in dir-spec.txt and tor-spec.txt, the latter mostly for the
    padding and encoding used in the creation of an OR's keys.

    For the "router" line in a networkstatus document, the following encodings
    are specified:

    From dir-spec.txt, commit 36761c7d5, L1504-1512:
      |
      |                                 […] "Identity" is a hash of its
      | identity key, encoded in base64, with trailing equals sign(s)
      | removed.  "Digest" is a hash of its most recent descriptor as
      | signed (that is, not including the signature), encoded in base64.
      |

    Before the hash digest of an OR's identity key is base64-encoded for
    inclusion in a networkstatus document, the hash digest is created in the
    following manner:

    From tor-spec.txt, commit 36761c7d5, L109-110:
      |
      | When we refer to "the hash of a public key", we mean the SHA-1 hash of the
      | DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).
      |

    From tor-spec.txt, commit 36761c7d5, L785-787:
      |
      | The "legacy identity" and "identity fingerprint" fields are the SHA1
      | hash of the PKCS#1 ASN1 encoding of the next onion router's identity
      | (signing) key.  (See 0.3 above.)
      |

    :param boolean bridge: If False, generate a server OR ID key, a signing
        key, and a TLS certificate/key pair. If True, generate a client ID key
        as well.
    :param string digest: The digest to use. (default: 'sha1')
    :returns: The server ID key, and a tuple of strings (fingerprint,
       onion-key, signing-key), where onion-key and secret key are the strings
       which should directly go into a server-descriptor. There are a *ton* of
       keys and certs in the this function. If you need more for some reason,
       this is definitely the thing you want to modify.
    """
    serverID = rsa.createKey(True)
    SIDSKey, SIDSCert, SIDPKey, SIDPCert = serverID
    serverLinkCert = tls.createTLSLinkCert()
    serverLinkCert.sign(SIDSKey, digest)

    if bridge:
        # For a bridge, a "client" ID key is used to generate the fingerprint
        clientID = rsa.createKey(True)
        CIDSKey, CIDSCert, CIDPKey, CIDPCert = clientID

        # XXX I think we're missing some of the signatures
        #     see torspec.git/tor-spec.txt §4.2 on CERTS cells
        clientLinkCert = tls.createTLSLinkCert()
        clientLinkCert.sign(CIDSKey, digest)
    else:
        CIDSKey, CIDSCert, CIDPKey, CIDPCert = serverID

    signing = rsa.createKey()
    signSKey, signSCert, signPKey, signPCert = signing
    onion = rsa.createKey()
    onionSKey, onionSCert, onionPKey, onionPCert = onion

    onionKeyString   = 'onion-key\n%s' % tls.getPublicKey(onionPCert)
    signingKeyString = 'signing-key\n%s' % tls.getPublicKey(signPCert)

    return SIDSKey, SIDPCert, (onionKeyString, signingKeyString)
