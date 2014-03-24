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
from __future__ import unicode_literals

from leekspin import const
from leekspin import util


def generateExtraInfo(nickname, fingerprint, ts, ipv4, port):
    """Create an OR extra-info document.

    See §2.2 "Extra-info documents" in torspec.git/dir-spec.txt.

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
    extra.append("extra-info %s %s" % (nickname, fingerprint))
    extra.append("published %s" % ts)
    extra.append("write-history %s (900 s) 3188736,2226176,2866176" % ts)
    extra.append("read-history %s (900 s) 3891200,2483200,2698240" % ts)
    extra.append("dirreq-write-history %s (900 s) 1024,0,2048" % ts)
    extra.append("dirreq-read-history %s (900 s) 0,0,0" % ts)
    extra.append("geoip-db-digest %s" % util.getHexString(40))
    extra.append("geoip6-db-digest %s" % util.getHexString(40))
    extra.append("dirreq-stats-end %s (86400 s)" % ts)
    extra.append("dirreq-v3-ips")
    extra.append("dirreq-v3-reqs")
    extra.append("dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0")
    extra.append("dirreq-v3-direct-dl complete=0,timeout=0,running=0")
    extra.append("dirreq-v3-tunneled-dl complete=12,timeout=0,running=0")
    extra.append("transport obfs3 %s:%d" % (ipv4, port + 1))
    extra.append("transport obfs2 %s:%d" % (ipv4, port + 2))
    extra.append("bridge-stats-end %s (86400 s)" % ts)
    extra.append("bridge-ips ca=8")
    extra.append("bridge-ip-versions v4=8,v6=0")
    extra.append("bridge-ip-transports <OR>=8")
    extra.append("router-signature\n")

    return '\n'.join(extra)
