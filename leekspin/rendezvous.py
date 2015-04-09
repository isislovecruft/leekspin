# -*- coding: utf-8 -*-

"""Functions for creating mock Hidden Service
``rendezvous-service-descriptors``.


An example Hidden Service descriptor
====================================
..
   This HS descriptor was taken from dgoulet's tor branch bug14847_027_05, from
   the file src/test/test_hs.c.

This is `DuckDuckGo`_'s actual Hidden Service
``rendezvous-service-descriptor`` for their search service at
http://3g2upl4pq6kufc4m.onion/::

    rendezvous-service-descriptor g5ojobzupf275beh5ra72uyhb3dkpxwg\r\n\
    version 2\r\n\
    permanent-key\r\n\
    -----BEGIN RSA PUBLIC KEY-----\r\n\
    MIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE\r\n\
    aZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg\r\n\
    I5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=\r\n\
    -----END RSA PUBLIC KEY-----\r\n\
    secret-id-part anmjoxxwiupreyajjt5yasimfmwcnxlf\r\n\
    publication-time 2015-03-11 19:00:00\r\n\
    protocol-versions 2,3\r\n\
    introduction-points\r\n\
    -----BEGIN MESSAGE-----\r\n\
    aW50cm9kdWN0aW9uLXBvaW50IDd1bnd4cmg2dG5kNGh6eWt1Z3EzaGZzdHduc2ll\r\n\
    cmhyCmlwLWFkZHJlc3MgMTg4LjEzOC4xMjEuMTE4Cm9uaW9uLXBvcnQgOTAwMQpv\r\n\
    bmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\r\n\
    QUxGRVVyeVpDbk9ROEhURmV5cDVjMTRObWVqL1BhekFLTTBxRENTNElKUWh0Y3g1\r\n\
    NXpRSFdOVWIKQ2hHZ0JqR1RjV3ZGRnA0N3FkdGF6WUZhVXE2c0lQKzVqeWZ5b0Q4\r\n\
    UmJ1bzBwQmFWclJjMmNhYUptWWM0RDh6Vgpuby9sZnhzOVVaQnZ1cWY4eHIrMDB2\r\n\
    S0JJNmFSMlA2OE1WeDhrMExqcUpUU2RKOE9idm9yQWdNQkFBRT0KLS0tLS1FTkQg\r\n\
    UlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQ\r\n\
    VUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTnJHb0ozeTlHNXQzN2F2ekI1cTlwN1hG\r\n\
    VUplRUVYMUNOaExnWmJXWGJhVk5OcXpoZFhyL0xTUQppM1Z6dW5OaUs3cndUVnE2\r\n\
    K2QyZ1lRckhMMmIvMXBBY3ZKWjJiNSs0bTRRc0NibFpjRENXTktRbHJnRWN5WXRJ\r\n\
    CkdscXJTbFFEaXA0ZnNrUFMvNDVkWTI0QmJsQ3NGU1k3RzVLVkxJck4zZFpGbmJr\r\n\
    NEZIS1hBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJv\r\n\
    ZHVjdGlvbi1wb2ludCBiNGM3enlxNXNheGZzN2prNXFibG1wN3I1b3pwdHRvagpp\r\n\
    cC1hZGRyZXNzIDEwOS4xNjkuNDUuMjI2Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1r\r\n\
    ZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU8xSXpw\r\n\
    WFFUTUY3RXZUb1NEUXpzVnZiRVFRQUQrcGZ6NzczMVRXZzVaUEJZY1EyUkRaeVp4\r\n\
    OEQKNUVQSU1FeUE1RE83cGd0ak5LaXJvYXJGMC8yempjMkRXTUlSaXZyU29YUWVZ\r\n\
    ZXlMM1pzKzFIajJhMDlCdkYxZAp6MEswblRFdVhoNVR5V3lyMHdsbGI1SFBnTlI0\r\n\
    MS9oYkprZzkwZitPVCtIeGhKL1duUml2QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBV\r\n\
    QkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\r\n\
    S0VZLS0tLS0KTUlHSkFvR0JBSzNWZEJ2ajFtQllLL3JrcHNwcm9Ub0llNUtHVmth\r\n\
    QkxvMW1tK1I2YUVJek1VZFE1SjkwNGtyRwpCd3k5NC8rV0lGNFpGYXh5Z2phejl1\r\n\
    N2pKY1k3ZGJhd1pFeG1hYXFCRlRwL2h2ZG9rcHQ4a1ByRVk4OTJPRHJ1CmJORUox\r\n\
    N1FPSmVMTVZZZk5Kcjl4TWZCQ3JQai8zOGh2RUdrbWVRNmRVWElvbVFNaUJGOVRB\r\n\
    Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlv\r\n\
    bi1wb2ludCBhdjVtcWl0Y2Q3cjJkandsYmN0c2Jlc2R3eGt0ZWtvegppcC1hZGRy\r\n\
    ZXNzIDE0NC43Ni44LjczCm9uaW9uLXBvcnQgNDQzCm9uaW9uLWtleQotLS0tLUJF\r\n\
    R0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTzVweVZzQmpZQmNmMXBE\r\n\
    dklHUlpmWXUzQ05nNldka0ZLMGlvdTBXTGZtejZRVDN0NWhzd3cyVwpjejlHMXhx\r\n\
    MmN0Nkd6VWkrNnVkTDlITTRVOUdHTi9BbW8wRG9GV1hKWHpBQkFXd2YyMVdsd1lW\r\n\
    eFJQMHRydi9WCkN6UDkzcHc5OG5vSmdGUGRUZ05iMjdKYmVUZENLVFBrTEtscXFt\r\n\
    b3NveUN2RitRa25vUS9BZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0t\r\n\
    LS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpN\r\n\
    SUdKQW9HQkFMVjNKSmtWN3lTNU9jc1lHMHNFYzFQOTVRclFRR3ZzbGJ6Wi9zRGxl\r\n\
    RlpKYXFSOUYvYjRUVERNClNGcFMxcU1GbldkZDgxVmRGMEdYRmN2WVpLamRJdHU2\r\n\
    SndBaTRJeEhxeXZtdTRKdUxrcXNaTEFLaXRLVkx4eGsKeERlMjlDNzRWMmJrOTRJ\r\n\
    MEgybTNKS2tzTHVwc3VxWWRVUmhOVXN0SElKZmgyZmNIalF0bEFnTUJBQUU9Ci0t\r\n\
    LS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KCg==\r\n\
    -----END MESSAGE-----\r\n\
    signature\r\n\
    -----BEGIN SIGNATURE-----\r\n\
    d4OuCE5OLAOnRB6cQN6WyMEmg/BHem144Vec+eYgeWoKwx3MxXFplUjFxgnMlmwN\r\n\
    PcftsZf2ztN0sbNCtPgDL3d0PqvxY3iHTQAI8EbaGq/IAJUZ8U4y963dD5+Bn6JQ\r\n\
    myE3ctmh0vy5+QxSiRjmQBkuEpCyks7LvWvHYrhnmcg=\r\n\
    -----END SIGNATURE-----

.. _DuckDuckGo: https://duckduckgo.com
"""

import base64
import datetime
import hashlib
import logging
import random
import time

from Crypto.Cipher import AES
from Crypto.Util import Counter

from leekspin import crypto
from leekspin import util
from leekspin.const import TOKEN_HS_PROTO_VERSIONS
from leekspin.const import TOKEN_HS_PUBLICATION
from leekspin.const import TOKEN_PERMANENT_KEY
from leekspin.const import TOKEN_REND_SERV
from leekspin.const import TOKEN_SECRET_ID_PART
from leekspin.const import TOR_BEGIN_MSG
from leekspin.const import TOR_END_MSG
from leekspin.torversions import shouldSupportHSIntroV0


def calculateSecretIDPart(permanentID, currentTime, descriptorCookie=None,
                          replica=0):
    """Calculate the current ``secret-id-part`` for a Hidden Service.

    .. note: This is used in :func:`generateRendServiceLine` to calculate the
        Hidden Service's current ``descriptor-id``.

    From `rend-spec.txt`_ §1.3::

        "secret-id-part" SP secret-id-part NL

         [Exactly once]

         The result of the following operation as explained above, formatted as
         32 base32 chars. Using this secret id part, everyone can verify that
         the signed descriptor belongs to "descriptor-id".

             secret-id-part = H(time-period | descriptor-cookie | replica)

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt
    """
    H = hashlib.sha1
    permanentIDbyte = crypto.bytesToLong(permanentID[0])
    timePeriod = str((currentTime + permanentIDbyte * 86400 / 256) / 86400)

    secretID = H(str(timePeriod))
    if descriptorCookie:
        secretID.update(str(descriptorCookie))
    secretID.update(str(replica))

    secretIDPart = secretID.digest()
    secretIDB32 = base64.b32encode(secretIDPart).lower()
    secretIDPartLine = TOKEN_SECRET_ID_PART + secretIDB32

    return (secretIDPart, secretIDPartLine)

def createDescriptorCookie(length=128):
    """Create an Hidden Service descriptor-cookie.

    :param int length: The length of the cookie, in bits.
    :rtype: bytes
    :returns: A random bytestring of the specified **length**.
    """
    cookie = crypto.longToBytes(random.getrandbits(128))
    return cookie

def generateIntroPoints(descriptorCookie=None, introductionPoints=2):
    """Generate the ``introduction-points`` message for an HS descriptor.

    From `rend-spec.txt`_ §1.3::

        "introduction-points" NL encrypted-string

          [At most once]

           A list of introduction points. If the optional "descriptor-cookie" is
           used, this list is encrypted with AES in CTR mode with a random
           initialization vector of 128 bits that is written to
           the beginning of the encrypted string, and the "descriptor-cookie" as
           secret key of 128 bits length.

           The string containing the introduction point data (either encrypted
           or not) is encoded in base64, and surrounded with
           "-----BEGIN MESSAGE-----" and "-----END MESSAGE-----".

           The unencrypted string may begin with:

             "service-authentication" auth-type auth-data NL

               [Any number]

               The service-specific authentication data can be used to perform
               client authentication. This data is independent of the selected
               introduction point as opposed to "intro-authentication" below. The
               format of auth-data (base64-encoded or PEM format) depends on
               auth-type. See section 2 of this document for details on auth
               mechanisms.

           Subsequently, an arbitrary number of introduction point entries may
           follow, each containing the following data:

             "introduction-point" SP identifier NL

               [At start, exactly once]

               The identifier of this introduction point: the base32 encoded
               hash of this introduction point's identity key.

             "ip-address" SP ip4 NL

               [Exactly once]

               The IP address of this introduction point.

             "onion-port" SP port NL

               [Exactly once]

               The TCP port on which the introduction point is listening for
               incoming onion requests.

             "onion-key" NL a public key in PEM format

               [Exactly once]

               The public key that can be used to encrypt messages to this
               introduction point.

             "service-key" NL a public key in PEM format

               [Exactly once]

               The public key that can be used to encrypt messages to the hidden
               service.

             "intro-authentication" auth-type auth-data NL

               [Any number]

               The introduction-point-specific authentication data can be used
               to perform client authentication. This data depends on the
               selected introduction point as opposed to "service-authentication"
               above. The format of auth-data (base64-encoded or PEM format)
               depends on auth-type. See section 2 of this document for details
               on auth mechanisms.

            (This ends the fields in the encrypted portion of the descriptor.)

           [It's ok for Bob to advertise 0 introduction points. He might want
            to do that if he previously advertised some introduction points,
            and now he doesn't have any. -RD]

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt
    """
    # Tor stores all generated authorization data for the authorization
    # protocols described in Sections 2.1 and 2.2 in a new file using the
    # following file format:
    #
    #   "client-name" human-readable client identifier NL
    #   "descriptor-cookie" 128-bit key ^= 22 base64 chars NL
    #
    # If the authorization protocol of Section 2.2 is used, Tor also generates
    # and stores the following data:
    #
    #   "client-key" NL a public key in PEM format

    # "service-authentication" auth-type auth-data NL

    # XXX We only currently support authTupe 0 (REND_NO_AUTH).
    #authType = random.randint(0, 2)
    authType = 0

    if authType == 0:
        # XXX Do we need authData for REND_NO_AUTH? It seems from tor's source
        # that the "session-key" for the AES-CTR rounds is ``"(none)"``?
        authData = 'XXX'
    elif authType == 1:
        authData = 'XXX'
    elif authType == 2:
        # XXX Need client-key?
        authData = 'XXX'

    unencrypted = []

    # TODO: This part is *super* wastful.  In the future, we might want to
    # make it save the necessary descriptor keys from the generation of some
    # relay router descriptors, then reuse those pre-generated routers to pick
    # intro points and generate their unencrypted data strings.
    for i in range(introductionPoints):
        # "introduction-point" SP identifier NL
        (_, publicSigningKey, _) = crypto.generateSigningKey()
        (_, fingerprintBinary) = crypto.getFingerprint(publicSigningKey)
        identifier = base64.b32encode(fingerprintBinary).lower()
        # "onion-key" NL a public key in PEM format
        (secretOnionKey,
         publicOnionKey,
         publicOnionKeyLine) = crypto.generateOnionKey()
        # "service-key" NL a public key in PEM format
        (secretServiceKey,
         publicServiceKey,
         publicServiceKeyLine) = crypto.generateOnionKey()

        introPoint = []
        introPoint.append(b"introduction-point %s" % identifier)
        introPoint.append(b"ip-address %s" % util.randomIPv4())
        introPoint.append(b"onion-port %s" % util.randomPort())
        introPoint.append(publicOnionKeyLine)
        introPoint.append(publicServiceKeyLine.replace("onion-key", "service-key"))
        # XXX Need to implement intro-authentication auth-data:
        # "intro-authentication" auth-type auth-data NL
        if authType == 2:
            introPoint.append(b"intro-authentication %s" % (authType, authData))

        IP = "\n".join(introPoint)
        unencrypted.append(IP)

    unencrypted = "\n".join(unencrypted)

    # See §2.1 of rend-spec.txt
    if authType == 1 or authType == 2 or authType == 0:
        # When generating a hidden service descriptor, the service encrypts
        # the introduction-point part with a single randomly generated
        # symmetric 128-bit session key using AES-CTR as described for v2
        # hidden service descriptors in rend-spec. Afterwards, the service
        # encrypts the session key to all descriptor cookies using
        # AES. Authorized client should be able to efficiently find the
        # session key that is encrypted for him/her, so that 4 octet long
        # client ID are generated consisting of descriptor cookie and
        # initialization vector. Descriptors always contain a number of
        # encrypted session keys that is a multiple of 16 by adding fake
        # entries.  Encrypted session keys are ordered by client IDs in order
        # to conceal addition or removal of authorized clients by the service
        # provider.
        sessionKey = createDescriptorCookie()  # XXX last two bytes
        counter = Counter.new(128)
        ciphre = AES.new(sessionKey, mode=AES.MODE_CTR, IV=b"XXX", counter=counter)
        encrypted = ciphre.encrypt(unencrypted)
        encryptedB64 = base64.b64encode(encrypted)
        encryptedNoHeaders = crypto.chunkInto64CharsPerLine(encryptedB64,
                                                            separator=b"\r\n")
    # See §2.2 of rend-spec.txt
    #elif authType == 2:

    intros = []
    if authType != 0:
        intros.append(b"service-authentication %s %s" % (authType, authData))
    intros.append(b"introduction-points")
    intros.append(TOR_BEGIN_MSG)
    intros.append(encryptedNoHeaders)
    intros.append(TOR_END_MSG)

    introPoints = "\r\n".join(intros)
    return introPoints

def generatePublicationTimeLine(currentTime):
    """Generate a ``publication-time`` line for a Hidden Service descriptor.

    From `rend-spec.txt`_ §1.3::

        "publication-time" SP YYYY-MM-DD HH:MM:SS NL

          [Exactly once]

          A timestamp when this descriptor has been created.  It should be
          rounded down to the nearest hour.

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt

    :param int currentTime: The current time, in seconds since Epoch, as an
        integer.
    :rtype: str
    :returns: An Hidden Service ``publication-time`` line.
    """
    remainder = currentTime % 3600  # Round down to the nearest hour
    timestamp = datetime.datetime.fromtimestamp(currentTime - remainder)
    return TOKEN_HS_PUBLICATION + str(timestamp)

def generateRendServiceLine(permanentID, secretIDPart, replica=0):
    """Create the ``rendezvous-service-descriptor`` line for an HS descriptor.

    From `rend-spec.txt`_ §1.3::

        "rendezvous-service-descriptor" SP descriptor-id NL

          [At start, exactly once]

          Indicates the beginning of the descriptor. "descriptor-id" is a
          periodically changing identifier of 160 bits formatted as 32 base32
          chars that is calculated by the hidden service and its clients. The
          "descriptor-id" is calculated by performing the following operation:

            descriptor-id =
                H(permanent-id | H(time-period | descriptor-cookie | replica))

         "permanent-id" is the permanent identifier of the hidden service,
         consisting of 80 bits. It can be calculated by computing the hash value
         of the public hidden service key and truncating after the first 80 bits:

           permanent-id = H(public-key)[:10]

         Note: If Bob's OP has "stealth" authorization enabled (see Section 2.2),
         it uses the client key in place of the public hidden service key.

         "H(time-period | descriptor-cookie | replica)" is the (possibly
         secret) id part that is necessary to verify that the hidden service is
         the true originator of this descriptor and that is therefore contained
         in the descriptor, too. The descriptor ID can only be created by the
         hidden service and its clients, but the "signature" below can only be
         created by the service.

         "time-period" changes periodically as a function of time and
         "permanent-id". The current value for "time-period" can be calculated
         using the following formula:

           time-period = (current-time + permanent-id-byte * 86400 / 256)
                           / 86400

         "current-time" contains the current system time in seconds since
         1970-01-01 00:00, e.g. 1188241957. "permanent-id-byte" is the first
         (unsigned) byte of the permanent identifier (which is in network
         order), e.g. 143. Adding the product of "permanent-id-byte" and
         86400 (seconds per day), divided by 256, prevents "time-period" from
         changing for all descriptors at the same time of the day. The result
         of the overall operation is a (network-ordered) 32-bit integer, e.g.
         13753 or 0x000035B9 with the example values given above.

         "descriptor-cookie" is an optional secret password of 128 bits that
         is shared between the hidden service provider and its clients. If the
         descriptor-cookie is left out, the input to the hash function is 128
         bits shorter.

         "replica" denotes the number of the replica. A service publishes
         multiple descriptors with different descriptor IDs in order to
         distribute them to different places on the ring.

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt

    :param str permanentID: The permanent identifier of this Hidden Service,
        i.e. the HS's .onion address (without the ``.onion`` part at the end),
        as is returned from :func:`generatePermanentID`.
    :param str secretIDPart: The current ``secret-id-part`` for this
        **replica** number.  See :func:`calculateSecretIDPart`.
    :rtype: str
    :returns: An HS ``rendezvous-service-descriptor`` line.
    """
    H = hashlib.sha1
    descriptorID = H(permanentID + secretIDPart).digest()
    encoded = base64.b32encode(descriptorID).lower()
    line = TOKEN_REND_SERV + (b"%s" % encoded)
    return line

def generatePermanentKey(bits=1024):
    """Generate a Hidden Service's ``permanent-key``.

    From `rend-spec.txt`_ §1.3::

        "permanent-key" NL a public key in PEM format

          [Exactly once]

          The public key of the hidden service which is required to verify the
          "descriptor-id" and the "signature".

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt

    :param int bits: The length of the RSA key, in bits.
    :returns: A tuple of strings, ``(key-private, key-public, key-line)``,
       where ``key-line`` should be appropriate for placement directly into an
       hidden service descriptor.
    """
    (secretPermanentKey,
     publicPermanentKey,
     publicPermanentKeyNoHeaders) = crypto._generateRSAKey(bits)

    permanentKeyWithHeaders = crypto.addTorPKHeaderAndFooter(publicPermanentKeyNoHeaders)
    permanentKeyLine = TOKEN_PERMANENT_KEY + permanentKeyWithHeaders

    return (secretPermanentKey, publicPermanentKey, permanentKeyLine)

def generatePermanentID(publicPermanentKey):
    """Generate a Hidden Service's ``permanent-id``.

    From `rend-spec.txt`_ §1.3::

         "permanent-id" is the permanent identifier of the hidden service,
         consisting of 80 bits. It can be calculated by computing the hash value
         of the public hidden service key and truncating after the first 80 bits:

           permanent-id = H(public-key)[:10]

         Note: If Bob's OP has "stealth" authorization enabled (see Section 2.2),
         it uses the client key in place of the public hidden service key.

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt
    """
    permanentID = hashlib.sha1(publicPermanentKey).digest()[:10]
    return permanentID

def generateProtocolVersionsLine(version):
    """Generate a ``protocol-versions`` line for an HS descriptor.

    From `rend-spec.txt`_ §1.3::

        "protocol-versions" SP version-string NL

          [Exactly once]

          A comma-separated list of recognized and permitted version numbers
          for use in INTRODUCE cells; these versions are described in section
          1.8 below. Version numbers are positive integers.


    From `rend-spec.txt`_ §1.8::

        Alice builds a separate circuit to one of Bob's chosen introduction
        points, and sends it a RELAY_COMMAND_INTRODUCE1 cell containing:

          Cleartext
             PK_ID  Identifier for Bob's PK      [20 octets]
          Encrypted to Bob's PK: (in the v0 intro protocol)
             RP     Rendezvous point's nickname  [20 octets]
             RC     Rendezvous cookie            [20 octets]
             g^x    Diffie-Hellman data, part 1 [128 octets]
           OR (in the v1 intro protocol)
             VER    Version byte: set to 1.        [1 octet]
             RP     Rendezvous point nick or ID  [42 octets]
             RC     Rendezvous cookie            [20 octets]
             g^x    Diffie-Hellman data, part 1 [128 octets]
           OR (in the v2 intro protocol)
             VER    Version byte: set to 2.        [1 octet]
             IP     Rendezvous point's address    [4 octets]
             PORT   Rendezvous point's OR port    [2 octets]
             ID     Rendezvous point identity ID [20 octets]
             KLEN   Length of onion key           [2 octets]
             KEY    Rendezvous point onion key [KLEN octets]
             RC     Rendezvous cookie            [20 octets]
             g^x    Diffie-Hellman data, part 1 [128 octets]
           OR (in the v3 intro protocol)
             VER    Version byte: set to 3.        [1 octet]

           […]

        Through Tor 0.2.0.6-alpha, clients only generated the v0 introduction
        format, whereas hidden services have understood and accepted v0,
        v1, and v2 since 0.1.1.x. As of Tor 0.2.0.7-alpha and 0.1.2.18,
        clients switched to using the v2 intro format.

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt

    :param str version: One of :data:`leekspin.torversions.SERVER_VERSIONS`.
    :rtype: str
    :returns: An Hidden Service ``protocol-versions`` string.
    """
    if shouldSupportHSIntroV0(version):
        versions = '0,1,2'
    else:
        versions = '2,3'

    return TOKEN_HS_PROTO_VERSIONS + versions

def generateVersionLine(version):
    """Determine the appropriate version number of an HS descriptor.

    From `rend-spec.txt`_ §1.3::

        "version" SP version-number NL

          [Exactly once]

          The version number of this descriptor's format. Version numbers are a
          positive integer.

    .. _rend-spec.txt: https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt

    .. todo:: Which versions are which?  What does the ``version`` string in an
        Hidden Service ``rendezvous-service-descriptor`` mean?  Is it the
        revision number of the descriptor?  The supported handshake protocol
        version?  Currently, we just return the string ``"version 2"``, no
        matter what ``version`` is passed in.

    :param str version: One of :data:`leekspin.torversions.SERVER_VERSIONS`.
    :rtype: str
    :returns: An Hidden Service ``version`` string.
    """
    #return b"version %b" % version
    return b"version 2"
