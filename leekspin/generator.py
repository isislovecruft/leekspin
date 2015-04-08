# -*- coding: utf-8 -*-

"""Main leekspin module for generating descriptors and writing to disk.

.. authors:: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
             Matthew Finkel <sysrqb@torproject.org>
.. licence:: see LICENSE file for licensing details
.. copyright:: (c) 2013-2015 The Tor Project, Inc.
               (c) 2013-2015 Isis Lovecruft
               (c) 2013-2015 Matthew Finkel
"""

from __future__ import absolute_import
from __future__ import print_function

from codecs import open as open

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
from leekspin import server
from leekspin import tls
from leekspin import torversions
from leekspin import util

#: If pynacl was found by :attr:`leekspin.ntor.nacl`.
nacl = ntor.nacl


def generateDescriptors(bridge=True):
    """Create keys, certs, signatures, documents and descriptors for an OR.

    :returns:
        A 3-tuple of strings:
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

    (secretOnionKey, publicOnionKey, onionKeyLine) = crypto.generateOnionKey()
    (secretSigningKey, publicSigningKey, signingKeyLine) = crypto.generateSigningKey()

    secretNTORKey = None
    publicNTORKey = None
    if nacl:
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

def create(count, bridge=True):
    """Generate all types of descriptors and write them to files.

    :param integer count: How many sets of descriptors to generate, i.e. how
        many mock bridges/relays to create.
    """
    logging.info("Generating %d %sdescriptors..." %
                 (int(count), 'bridge ' if bridge else ''))
    logging.info("Generated router nicknames:")

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
                extrainfo, server, netstatus = generateDescriptors(bridge=bridge)
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
