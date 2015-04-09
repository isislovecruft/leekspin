#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Functionality for creating and working with NTOR keys.

For a description of the NTOR handshake protocol, as well as its requisite
keys, see §5.1.4 of `tor-spec.txt`_, as well as the NTOR handshake proposal_.

.. _tor-spec.txt: https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt
.. _proposal: https://gitweb.torproject.org/torspec.git/tree/proposals/216-ntor-handshake.txt
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import binascii
import logging
import warnings

# Get rid of the `UserWarning: reimporting '_cffi__x6e273d72xa4719796' might
# overwrite older definitions` warnings when importing nacl:
warnings.simplefilter('ignore', UserWarning, append=True)

nacl = None

try:
    import nacl
    import nacl.public
except (ImportError, NameError, IOError) as error:
    logging.warn("Could not import pyNaCl: https://github.com/pyca/pynacl. "\
                 "NTOR key generation will be disabled.")


class NTORKeyCreationError(Exception):
    """Raised when there was an error creating an NTOR key."""

class NTORPublicKeyError(Exception):
    """Raised when there is an error deriving the public Curve25519 key."""


def createNTORSecretKey():
    """Create a base64-encoded Curve25519 Salsa20-Poly1305 key.

    See §5.1.4 of `tor-spec.txt`_, as well as
    torspec.git/proposals/216-ntor-handshake.txt (specifically the
    "Integrating with the rest of Tor" section towards the end). For a full
    description of the Curve25519 keypair, see "Curve25519: new Diffie-Hellman
    speed records" by D.J. Bernstein.

    .. important:: The subkey used in the NTOR handshake protocol should be
        generated via HKDF-SHA256 as defined in :rfc:`5869`.

    .. _tor-spec.txt: https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt

    :raises: NTORKeyCreationError, if pynacl is not available or not
       installed, or if there was any other error while creating the key (such
       as an error due to having a different Python NaCl wrapper installed).

    :returns: The base64-encoded value of **NTORKey**, if available. The
       trailing newline of the base64 value is stripped (though not the
       padding, despite what proposals/216-ntor-handshake.txt
       says). Otherwise, returns None.
    """
    if nacl is None:
        raise NTORKeyCreationError("NTOR key creation requires pynacl.")
    else:
        try:
            #: The OR's private NTOR onion key.
            ntorSK = nacl.public.PrivateKey.generate()
        except Exception as error:
            raise NTORKeyCreationError("Error creating NTOR key: %s" % error)
        else:
            return ntorSK

def getNTORPublicKey(ntorSecretKey=None, base64=True):
    """Get the public key from the secret portion of a Curve25519 keypair.

    The **base64** version of the public Curve25519 key return from this
    function is suitable for use in a ``@type [bridge-]server-descriptor``.

    .. todo:: Remember to tell nickm to fix the description in his proposal
        about the ntor-onion-key padding removal.

    :type ntorSecretKey: ``nacl.public.PrivateKey``
    :param ntorSecretKey: A key created with :func:`createNTORSecretKey`. If
                          not given, a new one will be created automatically.
    :param bool base64: If ``True``, return the base64-encoded NTOR public key
                        (with trailing newline removed).
    :raises: :exc:`NTORPublicKeyError` if there was an error retrieving the
             public key.
    :rtype: str or ``nacl.public.PublicKey`` or ``None``
    :returns: The base64-encoded string version of the public portion of a
              Curve25519 keypair, if **base64** is ``True``, otherwise,
              returns the ``nacl.public.PublicKey``. Returns ``None``, if no
              **ntorSecretKey** was given and one could not be created.
    """
    if not ntorSecretKey:
        try:
            ntorSecretKey = createNTORSecretKey()
        except NTORKeyCreationError as error:
            logging.debug(error)

    if ntorSecretKey:
        try:
            #: The OR's public NTOR key; this goes into its
            #: ``@type [bridge]-server-descriptor``.
            ntorPublicKey = ntorSecretKey.public_key
            if base64:
                ntorPublicKey = binascii.b2a_base64(
                    bytearray(str(ntorPublicKey))).rstrip('\n').rstrip('==')
        except Exception as error:
            raise NTORPublicKeyError("Error retrieving the NTOR public key: %s"
                                     % error)
        else:
            return ntorPublicKey
