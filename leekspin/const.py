# -*- coding: utf-8 -*-

"""String constants.

The following are constant strings used within Tor and OpenSSL to facilitate
conversion between formats. Most are the ``-----BEGIN …-----`` and
``-----END…-----`` lines in PEM encoded keys and signatures.

================== =====================================================
Constant           Description
================== =====================================================
TOR_BEGIN_KEY      Found at the beginning of a public key
TOR_END_KEY        Found at the end of a public key
TOR_BEGIN_SK       Found at the beginning of a private key
TOR_END_SK         Found at the end of a private key
TOR_BEGIN_SIG      Found at the beginning of a signature
TOR_END_SIG        Found at the end of a signature
TOR_BEGIN_MSG      Found at the beginning of the encrypted ``introduction-points`` in an Hidden Service descriptor
TOR_END_MSG        Found at the end of the encrypted ``introduction-points`` in an Hidden Service descriptor
OPENSSL_BEGIN_KEY  Found at the beginning of all OpenSSL-generated keys
OPENSSL_END_KEY    Found at the end of all OpenSSL-generated keys
OPENSSL_BEGIN_CERT Found at the beginning of all OpenSSL-generated certs
OPENSSL_END_CERT   Found at the end of all OpenSSL-generated certs
================== =====================================================

Strings found in PEM-encoded objects created by Tor:
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals


#:
TOR_BEGIN_KEY = b"-----BEGIN RSA PUBLIC KEY-----"
#:
TOR_END_KEY   = b"-----END RSA PUBLIC KEY-----"
#:
TOR_BEGIN_SK  = b"-----BEGIN RSA PRIVATE KEY-----"
#:
TOR_END_SK    = b"-----END RSA PRIVATE KEY-----"
#:
TOR_BEGIN_SIG = b"-----BEGIN SIGNATURE-----"
#:
TOR_END_SIG   = b"-----END SIGNATURE-----"
#:
TOR_BEGIN_MSG = b"-----BEGIN MESSAGE-----"
#:
TOR_END_MSG   = b"-----END MESSAGE-----"


"""Tokens for ``[bridge-]server-descriptors``:"""

#:
TOKEN_SIGNING_KEY = b"signing-key\n"
#:
TOKEN_ONION_KEY = b"onion-key\n"
#:
TOKEN_ROUTER_SIGNATURE = b"router-signature\n"


"""Tokens for ``rendezvous-service-descriptors``:"""

#:
TOKEN_REND_SERV         = b"rendezvous-service-descriptor "
#:
TOKEN_PERMANENT_KEY     = b"permanent-key\r\n"
#:
TOKEN_SECRET_ID_PART    = b"secret-id-part "
#:
TOKEN_HS_PUBLICATION    = b"publication-time "
#:
TOKEN_HS_PROTO_VERSIONS = b"protocol-versions "
#:
TOKEN_HS_INTRO_POINTS   = b"introduction-points\r\n"
#:
TOKEN_HS_SIGNATURE      = b"signature\r\n"


"""Strings found in PEM-encoded objects created by OpenSSL:"""

#:
OPENSSL_BEGIN_KEY  = b"-----BEGIN PRIVATE KEY-----"
#:
OPENSSL_END_KEY    = b"-----END PRIVATE KEY-----"
#:
OPENSSL_BEGIN_CERT = b"-----BEGIN CERTIFICATE-----"
#:
OPENSSL_END_CERT   = b"-----END CERTIFICATE-----"

