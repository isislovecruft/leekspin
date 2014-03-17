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

import binascii


def generateNetstatus(nickname, idkey_digest, server_desc_digest, timestamp,
                      ipv4, orport, ipv6=None, dirport=None,
                      flags='Fast Guard Running Stable Valid',
                      bandwidth_line=None):
    """Generate an ``@type networkwork-status`` document (unsigned).

    DOCDOC

    :param str nickname: The router's nickname.
    :param string idkey_digest: The SHA-1 digest of the router's public identity
        key.
    :param XXX server_desc_digest: The SHA-1 digest of the router's
        ``@type [bridge-]server-descriptor``, before the descriptor is signed.
    :param XXX timestamp:
    """

    idkey_b64  = binascii.b2a_base64(idkey_digest)
    idb64      = str(idkey_b64).strip().rstrip('==')
    server_b64 = binascii.b2a_base64(server_desc_digest)
    srvb64     = str(server_b64).strip().rstrip('==')

    if bandwidth_line is not None:
        bw = int(bandwidth_line.split()[-1]) / 1024  # The 'observed' value
    dirport = dirport if dirport else 0

    status = []
    status.append("r %s %s %s %s %s %s %d" % (nickname, idb64, srvb64, timestamp,
                                              ipv4, orport, dirport))
    if ipv6 is not None:
        status.append("a [%s]:%s" % (ipv6, orport))
    status.append("s %s\nw Bandwidth=%s\np reject 1-65535\n" % (flags, bw))

    return '\n'.join(status)
