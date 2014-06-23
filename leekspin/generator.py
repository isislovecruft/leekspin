# -*- coding: utf-8 -*-

"""Main leekspin module for generating descriptors and writing to disk.

.. authors:: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
             Matthew Finkel <sysrqb@torproject.org>
.. licence:: see LICENSE file for licensing details
.. copyright:: (c) 2013-2014 The Tor Project, Inc.
               (c) 2013-2014 Isis Lovecruft
               (c) 2013-2014 Matthew Finkel
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

#: If the pynacl was found by :attr:`leekspin.ntor.nacl`.
nacl = ntor.nacl


def generateDescriptors():
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

    SIDSKey, SIDPCert, (onionkey, signingkey) = crypto.makeOnionKeys()
    idkeyPrivate = tls.getPrivateKey(SIDSKey)
    idkeyDigest = hashlib.sha1(idkeyPrivate).digest()

    idkeyPublic = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1,
                                                 SIDPCert.get_pubkey())
    idkeyPublic = re.sub(const.OPENSSL_BEGIN_KEY, '', idkeyPublic)
    idkeyPublic = re.sub(const.OPENSSL_END_KEY, '', idkeyPublic)
    idkeyPublic = idkeyPublic.strip()

    identDigest = hashlib.sha1(idkeyPublic).digest()
    fingerprint = hashlib.sha1(idkeyPublic).hexdigest().upper()
    fpr = crypto.convertToSpaceyFingerprint(fingerprint)

    extrainfoDoc = extrainfo.generateExtraInfo(nick, fingerprint,
                                               timestamp, ipv4, port)
    extrainfoDigest = hashlib.sha1(extrainfoDoc).digest()
    extrainfoHexdigest = hashlib.sha1(extrainfoDoc).hexdigest().upper()
    extrainfoSig = crypto.signDescriptorDigest(SIDSKey, extrainfoDigest)
    extrainfoDesc = extrainfoDoc + extrainfoSig

    serverDoc = []
    serverDoc.append("@purpose bridge")
    serverDoc.append("router %s %s %s 0 0" % (nick, ipv4, port))
    serverDoc.append("or-address [%s]:%s" % (ipv6, port))
    serverDoc.append("platform Tor %s on Linux" % vers)
    serverDoc.append("%s\npublished %s" % (protocols, timestamp))
    serverDoc.append("%s" % server.makeFingerprintLine(fingerprint, vers))
    serverDoc.append("uptime %s\n%s" % (uptime, bandwidth))
    serverDoc.append("%s" % server.makeExtraInfoDigestLine(extrainfoHexdigest,
                                                           vers))
    serverDoc.append("%s%s%s" % (onionkey, signingkey,
                                 server.makeHSDirLine(vers)))
    serverDoc.append("contact Somebody <somebody@example.com>")
    if nacl is not None:
        ntorkey = ntor.getNTORPublicKey()
        if ntorkey is not None:
            serverDoc.append("ntor-onion-key %s" % ntorkey)
    serverDoc.append("reject *:*\nrouter-signature\n")

    serverDesc = '\n'.join(serverDoc)
    serverDescDigest = hashlib.sha1(serverDesc).digest()

    netstatusDesc = netstatus.generateNetstatus(nick, identDigest,
                                                serverDescDigest, timestamp,
                                                ipv4, port, ipv6=ipv6,
                                                bandwidth_line=bandwidth)
    serverDesc += crypto.signDescriptorDigest(SIDSKey, serverDescDigest)
    return extrainfoDesc, serverDesc, netstatusDesc

def create(count):
    """Generate all types of descriptors and write them to files.

    :param integer count: How many sets of descriptors to generate, i.e. how
        many mock bridges/relays to create.
    """
    logging.info("Generating %d bridge descriptors..." % int(count))
    logging.info("Generated router nicknames:")

    server_descriptors    = list()
    netstatus_consensus   = list()
    extrainfo_descriptors = list()
    try:
        # Add headers:
        netstatus_consensus.append(
            ('flag-thresholds stable-uptime=613624 stable-mtbf=2488616 '
             'fast-speed=15000 guard-wfu=98.000% guard-tk=691200 '
             'guard-bw-inc-exits=55000 guard-bw-exc-exits=55000 enough-mtbf=1 '
             'ignoring-advertised-bws=0'))

        for i in xrange(int(count)):
            try:
                extrainfo, server, netstatus = generateDescriptors()
            except Exception as error:
                err, msg, tb = sys.exc_info()
                try:
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

        cached = "cached-extrainfo.new"
        descriptor_files = {
            "networkstatus-bridges": ''.join(netstatus_consensus),
            "bridge-descriptors": ''.join(server_descriptors),
            "cached-extrainfo.new": ''.join(extrainfo_descriptors)}

        if not os.path.isfile(cached):
            with open(cached, 'wb') as fh:
                fh.flush()
        if os.path.isfile(cached):
            os.rename(cached, "cached-extrainfo")

        for fn, giantstring in descriptor_files.items():
            util.writeDescToFile(fn, giantstring)
        logging.info("Done.")
        code = 0
        sys.exit(code)
