# -*- coding: utf-8 -*-

"""Main leekspin module for generating mocked Onion Relay (OR) and Hidden
Service (HS) descriptors and writing them to disk.
"""

from __future__ import absolute_import
from __future__ import print_function

from codecs import open as open

import base64
import hashlib
import logging
import random
import re
import sys
import os
import traceback

try:
    import OpenSSL
    import OpenSSL.crypto
except (ImportError, NameError) as error:
    print("This script requires pyOpenSSL>=0.14.0")
    raise SystemExit(error.message)

import OpenSSL
import OpenSSL.crypto

from leekspin import const
from leekspin import crypto
from leekspin import extrainfo
from leekspin import netstatus
from leekspin import nicknames
from leekspin import ntor
from leekspin import rendezvous
from leekspin import server
from leekspin import tls
from leekspin import torversions
from leekspin import util

#: If pynacl was found by :attr:`leekspin.ntor.nacl`.
nacl = True if ntor.nacl else False


def generateDescriptors(bridge=True, withoutTAP=False, withoutNTOR=False):
    """Create keys, certs, signatures, documents and descriptors for an OR.

    :param bool bridge: If ``True``, generate Bridge descriptors; otherwise,
        generate Relay descriptors.
    :param bool withoutTAP: If ``True``, generate descriptors without
        support for the TAP handshake, e.g. without RSA keys.
    :param bool withoutTAP: If ``True``, generate descriptors without
        support for the ntor handshake, e.g. without Ed25519 keys.
    :returns: A 3-tuple of strings:

      - a ``@type [bridge-]extra-info`` descriptor,
      - a ``@type [bridge-]server-descriptor``, and
      - a ``@type network-status`` document

      for a mock Tor relay/bridge.
    """
    ipv4 = util.randomIPv4()
    ipv6 = util.randomIPv6()
    port = util.randomPort()

    nick = nicknames.generateNickname()
    vers = torversions.getRandomVersion()
    uptime = int(random.randint(1800, 63072000))
    bandwidth = server.makeBandwidthLine()
    timestamp = util.makeTimeStamp(variation=True, period=36)
    protocols = server.makeProtocolsLine(vers)

    if withoutTAP:
        (secretOnionKey, publicOnionKey, onionKeyLine) = (None, None, None)
    else:
        (secretOnionKey, publicOnionKey, onionKeyLine) = crypto.generateOnionKey()
    (secretSigningKey, publicSigningKey, signingKeyLine) = crypto.generateSigningKey()

    secretNTORKey = None
    publicNTORKey = None

    if not withoutNTOR and nacl:
        try:
            secretNTORKey = ntor.createNTORSecretKey()
            publicNTORKey = ntor.getNTORPublicKey(secretNTORKey)
        except ntor.NTORKeyCreationError as error:
            secretNTORKey = None
            publicNTORKey = None
        
    (fingerprintSpacey, fingerprintBinary) = crypto.getFingerprint(publicSigningKey)
    fingerprintSmooshed = crypto.convertToSmooshedFingerprint(fingerprintSpacey)

    extrainfoDoc = extrainfo.generateExtraInfo(nick, fingerprintSmooshed,
                                               timestamp, ipv4, port, bridge=bridge)
    (extrainfoDigestBinary,
     extrainfoDigest,
     extrainfoDigestPKCS1) = crypto.digestDescriptorContent(extrainfoDoc)
    extrainfoDesc = crypto.signDescriptorContent(extrainfoDoc,
                                                 secretSigningKey,
                                                 digest=extrainfoDigestPKCS1)

    serverDoc = server.generateServerDescriptor(nick, fingerprintSpacey,
                                                timestamp, ipv4, ipv6, port,
                                                vers, protocols, uptime,
                                                bandwidth, extrainfoDigest,
                                                onionKeyLine, signingKeyLine,
                                                publicNTORKey, bridge=bridge)
    (serverDigestBinary,
     serverDigest,
     serverDigestPKCS1) = crypto.digestDescriptorContent(serverDoc)

    if bridge:
        serverDoc = b'@purpose bridge\n' + serverDoc

    serverDesc = crypto.signDescriptorContent(serverDoc,
                                              secretSigningKey,
                                              digest=serverDigestPKCS1)

    netstatusDesc = netstatus.generateBridgeNetstatus(nick, fingerprintBinary,
                                                      serverDigestBinary,
                                                      timestamp, ipv4, port,
                                                      ipv6=ipv6,
                                                      bandwidth_line=bandwidth)

    return (extrainfoDesc, serverDesc, netstatusDesc)

def generateHSDesc(replica):
    """Generate a ``@type rendezvous-service-descriptor`` for an Hidden
    Service.

    .. todo:: Make generation of ``permanent_ids`` deal with HS "stealth"
        authorisation.
    .. todo:: Implement per-client ``session_keys`` and
        ``descriptor_cookies``, see rend-spec.txt §2.1.

    :param int replica: The ``replica`` number for this particular descriptor.
        This influences the ``secret-id-part`` of the descriptor (see
        :func:`~leekspin.rendezvous.calculateSecretIDPart`).
    :rtype: str
    :returns: A ``@type rendezvous-service-descriptor`` as a string.
    """
    import time

    vers = torversions.getRandomVersion()
    versionsLine = rendezvous.generateVersionLine(vers)
    protocolVersionsLine = rendezvous.generateProtocolVersionsLine(vers)

    (secretPermanentKey,
     publicPermanentKey,
     permanentKeyLine) = rendezvous.generatePermanentKey()

    (secretSigningKey,
     publicSigningKey,
     signingKeyLine) = crypto.generateSigningKey()

    # TODO: Make generation of permanent_ids deal with HS "stealth" authorisation.
    permanentID = rendezvous.generatePermanentID(publicPermanentKey)

    # TODO: Implement per-client session-keys / descriptor cookies, see
    #       rend-spec.txt §2.1.
    descCookie = rendezvous.createDescriptorCookie()
    descCookieB64 = base64.b64encode(descCookie)#.strip("=")
    # see rendclient.c rend_parse_service_authorization()↑↑↑

    logging.info(("# Generated HS .onion address: %s\n"
                  "# Generated HS descriptor cookie: %s") %
                 (permanentID.encode("hex") + ".onion", descCookieB64))

    currentTime = int(time.time())
    publicationTimeLine = rendezvous.generatePublicationTimeLine(currentTime)
    (secretIDPart,
     secretIDLine) = rendezvous.calculateSecretIDPart(permanentID, currentTime,
                                                      descCookieB64, replica)
    introductionPoints = rendezvous.generateIntroPoints(descCookieB64)
    rendServiceLine = rendezvous.generateRendServiceLine(permanentID,
                                                         secretIDPart, replica)
    d = []
    d.append(rendServiceLine)
    d.append(versionsLine)
    d.append(permanentKeyLine)
    d.append(secretIDLine)
    d.append(publicationTimeLine)
    d.append(protocolVersionsLine)
    d.append(introductionPoints)
    d.append(const.TOKEN_HS_SIGNATURE)

    document = "\r\n".join(d) + "\r\n"
    (_, _, documentDigestPKCS1) = crypto.digestDescriptorContent(document)
    descriptor = crypto.signDescriptorContent(document, secretSigningKey,
                                              token=const.TOKEN_HS_SIGNATURE)
    # "router-signature" is for relay/bridge descriptor signatures; we have to
    # replace it with just "signature":
    descriptor = descriptor.replace("router-signature", "signature")
    logging.info("%s\n" % descriptor)

    return descriptor

def createHiddenServiceDescriptors(count, replicas=2):
    """Generate hidden service descriptors.

    :param int count: How many sets of descriptors to generate. This
       essentially corresponds to the number of fake ``.onion`` s which should
       be mocked.
    :param int replicas: The number of times which one particular mocked
       Hidden Service should "replicate" its descriptor in the Tor Network's
       ``HSDir`` hashring.  The default for real Hidden Services created with
       Tor is ``2``.
    """
    logging.info("Generating %d hidden service descriptors..." % count)

    rendDescriptors = list()

    try:
        for i in range(int(count)):
            # Create replicas from [1, **replicas**], inclusive:
            for j in range(1, int(replicas)):
                desc = generateHSDesc(j)
                rendDescriptors.append(desc)
    except KeyboardInterrupt as keyint:
        logging.warn("Received keyboard interrupt.")
        logging.warn("Stopping descriptor creation and exiting.")
        code = 1515
    except Exception as error:
        logging.exception(error)
    finally:
        logging.info("Writing descriptors to files...")

        descriptorFiles = {
                "rendezvous-service-descriptors": '\n'.join(rendDescriptors)}

        for fn, giantstring in descriptorFiles.items():
            util.writeDescToFile(fn, giantstring)

        logging.info("Done.")
        code = 0
        sys.exit(code)

def createRelayOrBridgeDescriptors(count, bridge=True, **kwargs):
    """Generate all types of descriptors and write them to files.

    :param int count: How many sets of descriptors to generate, i.e. how
        many mock bridges/relays to create.
    :param bool bridge: If ``True``, generate Bridge descriptors; otherwise,
        generate Relay descriptors.
    """
    logging.info("Generating %d %s descriptors..." %
                 (int(count), 'bridge' if bridge else 'relay'))
    logging.info("Generated router nicknames:")

    withoutTAP = False
    withoutNTOR = False

    if kwargs:
        if "withoutTAP" in kwargs:
            withoutTAP = kwargs.get("withoutTAP")
        if "withoutNTOR" in kwargs:
            withoutNTOR = kwargs.get("withoutNTOR")

    server_descriptors    = list()
    netstatus_consensus   = list()
    extrainfo_descriptors = list()
    try:
        # Add headers:
        netstatus_consensus.append(
            (b'flag-thresholds stable-uptime=613624 stable-mtbf=2488616 '
             'fast-speed=15000 guard-wfu=98.000% guard-tk=691200 '
             'guard-bw-inc-exits=55000 guard-bw-exc-exits=55000 enough-mtbf=1 '
             'ignoring-advertised-bws=0\n'))

        for i in xrange(int(count)):
            try:
                (extrainfo,
                 server,
                 netstatus) = generateDescriptors(bridge=bridge,
                                                  withoutTAP=withoutTAP,
                                                  withoutNTOR=withoutNTOR)
            except Exception as error:
                err, msg, tb = sys.exc_info()
                try:
                    logging.debug(tb)
                    logging.error(error)
                except:
                    print(traceback.print_tb(tb))
                    print(error)
            else:
                server_descriptors.append(server)
                netstatus_consensus.append(netstatus)
                extrainfo_descriptors.append(extrainfo)
    except KeyboardInterrupt as keyint:
        logging.warn("Received keyboard interrupt.")
        logging.warn("Stopping descriptor creation and exiting.")
        code = 1515
    finally:
        logging.info("Writing descriptors to files...")

        cached = "cached-extrainfo"
        cachedNew = "cached-extrainfo.new"

        # TODO: the `networkstatus-bridges` file and the `cached-consensus`
        # file should be sorted by fingerprint.

        if bridge:
            descriptorFiles = {
                "networkstatus-bridges": ''.join(netstatus_consensus),
                "bridge-descriptors": ''.join(server_descriptors)}
        else:
            # TODO: make the `cached-consensus` file have the appropriate
            # consensus headers.
            descriptorFiles = {
                "cached-consensus": ''.join(netstatus_consensus),
                "cached-descriptors": ''.join(server_descriptors)}

        # Both bridges and relay extrainfos are stored in the same filenames
        descriptorFiles[cachedNew] = ''.join(extrainfo_descriptors)

        if not os.path.isfile(cachedNew):
            with open(cachedNew, 'wb') as fh:
                fh.flush()
        if os.path.isfile(cachedNew):
            os.rename(cachedNew, cached)

        for fn, giantstring in descriptorFiles.items():
            util.writeDescToFile(fn, giantstring)

        logging.info("Done.")
        code = 0
        sys.exit(code)

def create(count, descriptorType=None, withoutTAP=False, withoutNTOR=False):
    """Create **count** descriptors of type **descriptor_type**.

    :param int count: The number of descriptors to generate.
    :type descriptorType: str or ``None``
    :param descriptorType: One of ``"relay"``, ``"bridge"``,
        ``"hidden_service"``, or ``None``.
    :param bool withoutTAP: If ``True``, generate descriptors without
        support for the TAP handshake, e.g. without RSA keys.
    :param bool withoutTAP: If ``True``, generate descriptors without
        support for the ntor handshake, e.g. without Ed25519 keys.
    """
    logging.info("Creating descriptor type %s" % descriptorType)

    if descriptorType in ('bridge', 'relay'):
        bridge = bool(descriptorType == 'bridge')
        createRelayOrBridgeDescriptors(count, bridge=bridge,
                                       withoutTAP=withoutTAP,
                                       withoutNTOR=withoutNTOR)
    elif descriptorType in ('hidden_service',):
        createHiddenServiceDescriptors(count)
