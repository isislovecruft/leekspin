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

import binascii

import OpenSSL.crypto

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

def signDescriptorDigest(key, descriptorDigest, digest='sha1'):
    """Ugh...I hate OpenSSL.

    The extra-info-digest is a SHA-1 hash digest of the extrainfo document,
    that is, the entire extrainfo descriptor up until the end of the
    'router-signature' line and including the newline, but not the actual
    signature.

    The signature at the end of the extra-info descriptor is a signature of
    the above extra-info-digest. This signature is appended to the end of the
    extrainfo document, and the extra-info-digest is added to the
    'extra-info-digest' line of the [bridge-]server-descriptor.

    The first one of these was created with a raw digest, the second with a
    hexdigest. They both encode the the 'sha1' digest type if you check the
    `-asnparse` output (instead of `-raw -hexdump`).

    .. command:: openssl rsautl -inkey eiprivkey -verify -in eisig1 -raw -hexdump
      |
      | 0000 - 00 01 ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0050 - ff ff ff ff ff ff ff ff-ff ff ff ff 00 30 21 30   .............0!0
      | 0060 - 09 06 05 2b 0e 03 02 1a-05 00 04 14 42 25 41 fb   ...+........B%A.
      | 0070 - 82 ef 11 f4 5f 2c 95 53-67 2d bb fe 7f c2 34 7f   ...._,.Sg-....4.

    .. command:: openssl rsautl -inkey eiprivkey -verify -in eisig2 -raw -hexdump
      |
      | 0000 - 00 01 ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
      | 0050 - ff ff ff ff ff ff ff ff-ff ff ff ff 00 30 21 30   .............0!0
      | 0060 - 09 06 05 2b 0e 03 02 1a-05 00 04 14 44 30 ab 90   ...+........D0..
      | 0070 - 93 d1 08 21 df 87 c2 39-2a 04 1c a5 bb 34 44 cd   ...!...9*....4D.

    .. todo:: See the RSA PKCS_ Standard v2.2 for why this function is totally
       wrong.

    .. _PKCS: http://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf

    :type key: :class:`OpenSSL.crypto.PKey`
    :param key: An RSA private key.
    :param string descriptorDigest: The raw SHA-1 digest of any descriptor
        document.
    :param string digest: The digest to use. (default: 'sha1')
    """
    sig = binascii.b2a_base64(OpenSSL.crypto.sign(key, descriptorDigest,
                                                  digest))
    sigCopy = sig
    originalLength = len(sigCopy.replace('\n', ''))

    # Only put 64 bytes of the base64 signature per line:
    sigSplit = []
    while len(sig) > 0:
        sigSplit.append(sig[:64])
        sig = sig[64:]
    sigFormatted = '\n'.join(sigSplit)

    sigFormattedCopy = sigFormatted
    formattedLength = len(sigFormattedCopy.replace('\n', ''))

    if originalLength != formattedLength:
        print("WARNING: signDescriptorDocument(): %s"
              % "possible bad reformatting for signature.")
        print("DEBUG: signDescriptorDocument(): original=%d formatted=%d"
              % (originalLength, formattedLength))
        print("DEBUG: original:\n%s\nformatted:\n%s"
              % (sigCopy, sigFormatted))

    sigWithHeaders = const.TOR_BEGIN_SIG + '\n' \
                     + sigFormatted \
                     + const.TOR_END_SIG + '\n'
    return sigWithHeaders
