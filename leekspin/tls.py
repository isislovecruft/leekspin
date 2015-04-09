# -*- coding: utf-8 -*-

"""Utilities for working with OpenSSL x509 certificates and their keypairs."""

from __future__ import print_function
from __future__ import absolute_import

import logging
import random
import re
import time

import OpenSSL.crypto

from leekspin import const
from leekspin import util


PEM  = OpenSSL.crypto.FILETYPE_PEM


class OpenSSLInvalidFormat(Exception):
    """Raised if the specified file format is unsupported by OpenSSL."""


def attachKey(key, cert, selfsign=True, digest='sha1', pem=False):
    """Attach a key to a cert and optionally self-sign the cert.

    :type key: :class:`OpenSSL.crypto.PKey`
    :param key: A previously generated key, used to generate the other half of
        the keypair.
    :type cert: :class:`OpenSSL.crypto.X509`
    :param cert: A TLS certificate without a public key attached to it, such
        as one created with :func:`createTLSCert`.
    :param bool selfsign: If True, use the **key** to self-sign the **cert**.
        Note that if ``bool=True``, and you attempt to export the public key
        of a cert (e.g. in order to create another cert which *only* holds the
        public key), this function will raise several nasty OpenSSL
        errors. Instead, to get the *only* public key within an x509
        certificate, use ``public_key`` and/or ``public_cert`` from this
        example::

            secret_key = createRSAKey()
            secret_cert = attachKey(secret_key, createTLSCert(selfsign=True))
            public_key = secret_cert.get_pubkey()
            public_cert = attachKey(public_key, createTLSCert, selfsign=False)

        Otherwise, if you only called this function once, i.e. if you use the
        ``secret_cert`` in the previous example, it would contain both halves
        of the RSA keypair. **/me glares at the PyOpenSSL API designers**
        Indempotence, bitches, it is a thing!
    :param str digest: The digest to use. Check your OpenSSL installation
        to see which are supported. We pretty much only care about ``'sha1'``
        and ``'sha256'`` here.
    :param bool pem: If True, return a 3-tuple of PEM-encoded strings, one
        for each of ``(certificate, private_key, public_key)``, where:

        - ``certificate`` is the original **cert** with the **key** attached,
        - ``private_key`` is the private RSA modulus, primes, and exponents
          exported from the **cert**, and
        - ``public_key`` is the public RSA modulus exported from the **cert**.

    .. warning:: Enabling the **pem** parameter when passing in a key which
        has only the public RSA modulus (as described above) will result in
        *nasty* OpenSSL errors. Trust me, you do *not* want to try to parse
        OpenSSL's errors.

    :raises: An infinite, labyrinthine mire of non-Euclidean OpenSSL errors
        with non-deterministic messages and self-referential errorcodes,
        tangled upon itself in contempt of sanity, hope, and decent software
        engineering practices.
    :returns: If **pem** is ``True``, then the values described there are
        returned. Otherwise, returns the **cert** with the **key** attached to
        it.
    """
    # OpenSSL requires an ascii string, not unicode:
    digest = type('')(digest)

    # Attach the key to the certificate
    cert.set_pubkey(key)

    if selfsign:
        # Self-sign the cert with the key, using the specified hash digest
        cert.sign(key, digest)

    if pem:
        certificate = OpenSSL.crypto.dump_certificate(PEM, cert)
        private_key = OpenSSL.crypto.dump_privatekey(PEM, key)
        public_key = OpenSSL.crypto.dump_privatekey(PEM, cert.get_pubkey())
        return certificate, private_key, public_key
    return cert

def createTLSCert(lifetime=None):
    """Create a TLS certificate.

    :param int lifetime: The time, in seconds, that the certificate should
        remain valid for.
    :rtype: :class:`OpenSSL.crypto.X509`
    :returns: A certificate, unsigned, and without a key attached to it.
    """
    if not lifetime:
        # see `router_initialize_tls_context()` in src/or/router.c
        lifetime = 5 + random.randint(0, 361)
        lifetime = lifetime * 24 * 3600
        if int(random.getrandbits(1)):
            lifetime -= 1

    cert = OpenSSL.crypto.X509()

    timeFormat = lambda x: time.strftime("%Y%m%d%H%M%SZ", x)
    now = time.time()
    before = time.gmtime(now)
    after = time.gmtime(now + lifetime)
    cert.set_notBefore(timeFormat(before))
    cert.set_notAfter(timeFormat(after))

    return cert

def createTLSLinkCert(lifetime=7200):
    """Create a certificate for the TLS link layer.

    The TLS certificate used for the link layer between Tor relays, and
    between clients and their bridges/guards, has a shorter lifetime than the
    other certificates. Currently, in Tor, these certificates expire after two
    hours.

    :param int lifetime: The time, in seconds, that the certificate should
        remain valid for.
    :rtype: :class:`OpenSSL.crypto.X509`
    :returns: A certificate, unsigned, and without a key attached to it.
    """
    cert = createTLSCert(lifetime)
    cert.get_subject().CN = 'www.' + util.getHexString(16) + '.net'
    cert.get_issuer().CN = 'www.' + util.getHexString(10) + '.com'
    return cert

def _getFormat(fileformat):
    """Get the file format constant from OpenSSL.

    :param str fileformat: One of ``'PEM'`` or ``'ASN1'``.
    :raises OpenSSLInvalidFormat: If **fileformat** wasn't found.
    :returns: ``OpenSSL.crypto.PEM`` or ``OpenSSL.crypto.ASN1`` respectively.
    """
    fileformat = 'FILETYPE_' + fileformat
    fmt = getattr(OpenSSL.crypto, fileformat, None)
    if fmt is not None:
        return fmt
    else:
        raise OpenSSLInvalidFormat("Filetype format %r not found."% fileformat)

def getPublicKey(cert, fileformat='PEM'):
    """Retrieve the PEM public key, with Tor headers, from a certificate.

    :type cert: :class:`OpenSSL.crypto.X509`
    :param cert: A certificate with an attached key.
    :param str fileformat: One of ``'PEM'`` or ``'ASN1'``.
    :rtype: str
    :returns: The public key in the specified **fileformat**.
    """
    fmt = _getFormat(fileformat)
    publicKey = OpenSSL.crypto.dump_privatekey(fmt, cert.get_pubkey())
    # It says "PRIVATE KEY" just because the stupid pyOpenSSL wrapper is
    # braindamaged. You can check that it doesn't include the RSA private
    # exponents and primes by substituting ``OpenSSL.crypto.FILETYPE_TEXT``
    # for the above ``PEM``.
    publicKey = re.sub(const.OPENSSL_BEGIN_KEY,
                       const.TOR_BEGIN_KEY,
                       publicKey)
    publicKey = re.sub(const.OPENSSL_END_KEY,
                       const.TOR_END_KEY,
                       publicKey)
    return publicKey

def getPrivateKey(key, fileformat='PEM'):
    """Retrieve the PEM public key, with Tor headers, from a certificate.

    :type key: :class:`OpenSSL.crypto.PKey`
    :param key: A certificate with an attached key.
    :param str fileformat: One of ``'PEM'`` or ``'ASN1'``.
    :rtype: str
    :returns: The private key in the specified **fileformat**.
    """
    fmt = _getFormat(fileformat)
    privateKey = OpenSSL.crypto.dump_privatekey(fmt, key)
    privateKey = re.sub(const.OPENSSL_BEGIN_KEY,
                        const.TOR_BEGIN_SK,
                        privateKey)
    privateKey = re.sub(const.OPENSSL_END_KEY,
                        const.TOR_END_SK,
                        privateKey)
    return privateKey
