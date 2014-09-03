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

  addPKCS1Padding - PKCS#1 pad a message.
  convertToSpaceyFingerprint - Add space character delimiters to a fingerprint.

"""

from __future__ import print_function
from __future__ import absolute_import

import base64
import binascii
import codecs
import hashlib
import sys

from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from Crypto.Util.number import long_to_bytes

import OpenSSL.crypto

from leekspin import const
from leekspin import rsa
from leekspin import tls
from leekspin.const import TOR_BEGIN_KEY
from leekspin.const import TOR_END_KEY
from leekspin.const import TOR_BEGIN_SIG
from leekspin.const import TOR_END_SIG
from leekspin.const import TOKEN_ONION_KEY
from leekspin.const import TOKEN_ROUTER_SIGNATURE
from leekspin.const import TOKEN_SIGNING_KEY


class InvalidFingerprint(ValueError):
    """Raised when a key fingerprint is invalid."""


def addPKCS1Padding(message):
    """Add PKCS#1 padding to **message**.
    
    (PKCS#1 v1.0? see https://bugs.torproject.org/13042)
    
    Each block is 128 bytes total in size:

        * 2 bytes for the type info ('\x00\x01')
        * 1 byte for the separator ('\x00')
        * variable length padding ('\xFF')
        * variable length for the **message**

    :param str message: The message will be encoded as bytes before adding
        PKCS#1 padding.
    :rtype: bytes
    :returns: The PKCS#1 padded message.
    """
    #if sys.version_info.major == 3:
    #    if isinstance(message, unicode):
    #        message = codecs.latin_1_encode(message, 'replace')[0]
    #else:
    #    if isinstance(message, str):
    #        message = codecs.latin_1_encode(message, 'replace')[0]

    padding = b''
    typeinfo = b'\x00\x01'
    separator = b'\x00'

    for x in range(125 - len(message)):
        padding += b'\xFF'

    PKCS1paddedMessage = typeinfo + padding + separator + message
    assert len(PKCS1paddedMessage) == 128

    return PKCS1paddedMessage

def addTorPKHeaderAndFooter(publicKey):
    """Add the ``----BEGIN[...]`` and end headers to a **publicKey**.

    :param bytes publicKey: A headerless, chunked, base64-encoded,
        PKCS#1-padded, ASN.1 DER sequence string representation of a public
        RSA key.
    :rtype: bytes
    :returns: The same signature, with the headers which Tor uses around it.
    """
    return b'\n'.join([TOR_BEGIN_KEY, publicKey, TOR_END_KEY])

def addTorSigHeaderAndFooter(signature):
    """Add the ``----BEGIN[...]`` and end headers to a **signature**.

    :param bytes signature: A headerless, chunked, base64-encoded signature.
    :rtype: bytes
    :returns: The same signature, with the headers which Tor uses around it.
    """
    return b'\n'.join([TOR_BEGIN_SIG, signature, TOR_END_SIG])

def chunkInto64CharsPerLine(data, separator=b'\n'):
    """Chunk **data** into lines with 64 characters each.

    :param basestring data: The data to be chunked up.
    :keyword basestring separator: The character to use to join the chunked
        lines. (default: ``b'\n'``)
    :rtype: basestring
    :returns: The **data**, as a string, with 64 characters (plus the
        **separator** character), per line.
    """
    chunked = []

    while len(data) > 0:
        chunked.append(data[:64])
        data = data[64:]

    lines = separator.join(chunked)

    return lines

def convertToSmooshedFingerprint(fingerprint):
    """Convert to a space-delimited 40 character fingerprint

    Given a 49-character string, such as one returned from
    :func:`convertToSpaceyFingerprint`:
      |
      | 72C2 F0AE 1C14 F40E D37E D5F5 434B 6471 1A65 8E46
      |

    convert it to the following format:
      |
      | 72C2F0AE1C14F40ED37ED5F5434B64711A658E46
      |

    :param str fingerprint: A 49-character spacey fingerprint.
    :rtype: bytes
    :raises InvalidFingerprint: If the fingerprint isn't 49-bytes in length.
    :returns: A 40-character smooshed fingerprint without spaces.
    """
    if len(fingerprint) != 49:
        raise InvalidFingerprint("Invalid fingerprint (!= 49 bytes): %r"
                                 % fingerprint)
    return fingerprint.replace(' ', '')

def convertToSpaceyFingerprint(fingerprint):
    """Convert to a space-delimited 40-character fingerprint

    Given a 40 character string, usually the the SHA-1 hash of the
    DER encoding of an ASN.1 RSA public key, such as:
      |
      | 72C2F0AE1C14F40ED37ED5F5434B64711A658E46
      |

    convert it to the following format:
      |
      | 72C2 F0AE 1C14 F40E D37E D5F5 434B 6471 1A65 8E46
      |

    :param str fingerprint: A 40-character hex fingerprint.
    :rtype: bytes
    :raises InvalidFingerprint: If the fingerprint isn't 40 bytes in length.
    :returns: A 4-character space-delimited fingerprint.
    """
    if len(fingerprint) != 40:
        raise InvalidFingerprint("Invalid fingerprint (< 40 bytes): %r"
                                 % fingerprint)
    return b" ".join([fingerprint[i:i+4] for i in range(0, 40, 4)])

def digestDescriptorContent(content):
    # Create the descriptor digest:
    descriptorDigest = hashlib.sha1(content)
    descriptorDigestBinary = descriptorDigest.digest()
    descriptorDigestHex = descriptorDigest.hexdigest()
    descriptorDigestHexUpper = descriptorDigestHex.upper()
    descriptorDigestHexLower = descriptorDigestHex.lower()

    # Remove the hex encoding:
    descriptorDigestBytes = descriptorDigestHexLower.decode('hex_codec')

    # And add PKCS#1 padding:
    descriptorDigestPKCS1 = addPKCS1Padding(descriptorDigestBytes)

    return (descriptorDigestBinary, descriptorDigestHexUpper, descriptorDigestPKCS1)

def getASN1Sequence(privateKey):
    """Get an ASN.1 DER sequence string representation of the key's public
    modulus and exponent.

    :type privateKey: ``Crypto.PublicKey.RSA``
    :param privateKey: A private RSA key.
    :rtype: bytes
    :returns: The ASN.1 DER-encoded string representation of the public
        portions of the **privateKey**.
    """
    seq = asn1.DerSequence()
    seq.append(privateKey.n)
    seq.append(privateKey.e)
    asn1seqString = seq.encode()

    return asn1seqString

def getFingerprint(publicKey):
    """Get a digest of the ASN.1 DER-encoded **publicKey**.

    :type publicKey: str
    :param publicKey: A public key (as within the return parameters of
        :func:`generateOnionKey` or :func:`generateSigningKey`.)
    :rtype: str
    :returns: A spacey fingerprint.
    """
    keyDigest = hashlib.sha1(publicKey)
    keyDigestBinary = keyDigest.digest()
    keyDigestHex = keyDigest.hexdigest()
    keyDigestHexUpper = keyDigestHex.upper()
    keyDigestBytes = codecs.latin_1_encode(keyDigestHexUpper, 'replace')[0]

    fingerprint = convertToSpaceyFingerprint(keyDigestBytes)

    return (fingerprint, keyDigestBinary)

def generateOnionKey():
    """Generate a router's onion key, which is used to encrypt CERT cells.

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

    :returns: A tuple of strings,
       ``(onion-key-private, onion-key-public, onion-key-line)``, where
       ``onion-key-line`` should directly go into a server-descriptor.
    """
    secretOnionKey = RSA.generate(1024) # generate an RSA key
    publicOnionKey = getASN1Sequence(secretOnionKey) # ASN.1 encode it
    publicOnionKeyB64 = base64.b64encode(publicOnionKey) # base64 encode it
    
    # Split the base64-encoded string into lines 64 characters long:
    publicOnionKeyRaw = chunkInto64CharsPerLine(publicOnionKeyB64)

    # Add key header and footer:
    onionKeyWithHeaders = addTorPKHeaderAndFooter(publicOnionKeyRaw)
    onionKeyLine = TOKEN_ONION_KEY + onionKeyWithHeaders

    return (secretOnionKey, publicOnionKey, onionKeyLine)

def generateSigningKey():
    secretSigningKey = RSA.generate(1024) # generate an RSA key
    publicSigningKey = getASN1Sequence(secretSigningKey) # ASN.1 encode it
    publicSigningKeyB64 = base64.b64encode(publicSigningKey) # base64 encode it
    
    # Split the base64-encoded string into lines 64 characters long:
    publicSigningKeyRaw = chunkInto64CharsPerLine(publicSigningKeyB64)

    # Add key header and footer:
    signingKeyWithHeaders = addTorPKHeaderAndFooter(publicSigningKeyRaw)

    # Generate the new `signing-key` line for the descriptor:
    signingKeyLine = TOKEN_SIGNING_KEY + signingKeyWithHeaders

    return (secretSigningKey, publicSigningKey, signingKeyLine)

def signDescriptorContent(content, digest, privateKey):
    # Generate a signature by signing the PKCS#1-padded digest with the
    # private key:
    (signatureLong, ) = privateKey.sign(digest, None)
    signatureBytes = long_to_bytes(signatureLong, 128)
    signatureBase64 = base64.b64encode(signatureBytes)
    signature = chunkInto64CharsPerLine(signatureBase64)

    # Add the header and footer:
    signatureWithHeaders = addTorSigHeaderAndFooter(signature)

    # Add the signature to the descriptor content:
    routerSignatureLine = TOKEN_ROUTER_SIGNATURE + signatureWithHeaders

    rsStart = content.find(TOKEN_ROUTER_SIGNATURE)
    content = content[:rsStart] + routerSignatureLine + b'\n'

    return content
