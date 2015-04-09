# -*- coding: utf-8 -*-

"""Functions for creating mock ``extrainfo`` descriptors."""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
import random

from leekspin import const
from leekspin import util


def generateExtraInfo(nickname, fingerprint, ts, ipv4, port, bridge=True):
    """Create an OR extra-info document.

    See §2.2 "Extra-info documents" in dir-spec.txt_.

    For ``transport scramblesuit`` lines, the ``password`` parameter *always*
    is ``ABCDEFGHIJKLMNOPQRSTUVWXYZ234567``, i.e.::

        transport scramblesuit 10.0.1.111:4444 password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567


    .. _dir-spec.txt: https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt

    :param str nickname: The router's nickname.
    :param str fingerprint: A space-separated, hex-encoded, SHA-1 digest of
        the OR's private identity key. See :func:`convertToSpaceyFingerprint`.
    :param str ts: An ISO-8601 timestamp. See :func:`makeTimeStamp`.
    :param str ipv4: An IPv4 address.
    :param str port: The OR's ORPort.
    :rtype: str
    :returns: An extra-info document (unsigned).
    """
    extra = []
    extra.append(b"extra-info %s %s" % (nickname, fingerprint))
    extra.append(b"published %s" % ts)
    extra.append(b"write-history %s (900 s) 3188736,2226176,2866176" % ts)
    extra.append(b"read-history %s (900 s) 3891200,2483200,2698240" % ts)
    extra.append(b"dirreq-write-history %s (900 s) 1024,0,2048" % ts)
    extra.append(b"dirreq-read-history %s (900 s) 0,0,0" % ts)
    extra.append(b"geoip-db-digest %s" % util.getHexString(40))
    extra.append(b"geoip6-db-digest %s" % util.getHexString(40))
    extra.append(b"dirreq-stats-end %s (86400 s)" % ts)
    extra.append(b"dirreq-v3-ips")
    extra.append(b"dirreq-v3-reqs")
    extra.append(b"dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0")
    extra.append(b"dirreq-v3-direct-dl complete=0,timeout=0,running=0")
    extra.append(b"dirreq-v3-tunneled-dl complete=12,timeout=0,running=0")

    if bridge:
        scramblesuitPassword = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

        obfs4iatMode = bytes(random.getrandbits(1))  # 0 or 1
        # hexadecimal, 40 chars long:
        obfs4nodeID = hashlib.sha1(bytes(random.getrandbits(8))).hexdigest()
        # hexadecimal, 64 chars long:
        obfs4publicKey = hashlib.sha256(bytes(random.getrandbits(8))).hexdigest()

        extra.append(b"transport obfs3 %s:%d" % (ipv4, port + 1))
        extra.append(b"transport obfs2 %s:%d" % (ipv4, port + 2))
        extra.append(b"transport scramblesuit %s:%d password=%s" %
                     (ipv4, port + 3, scramblesuitPassword))
        # PT args are comma-separated in the bridge-extrainfo descriptors:
        extra.append(b"transport obfs4 %s:%d iat-mode=%s,node-id=%s,public-key=%s" %
                     (ipv4, port + 4, obfs4iatMode, obfs4nodeID, obfs4publicKey))
        extra.append(b"bridge-stats-end %s (86400 s)" % ts)
        extra.append(b"bridge-ips ca=8")
        extra.append(b"bridge-ip-versions v4=8,v6=0")
        extra.append(b"bridge-ip-transports <OR>=8")

    extra.append(b"router-signature\n")

    extrainfoDoc = b'\n'.join(extra)

    return extrainfoDoc
