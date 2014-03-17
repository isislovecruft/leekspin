# -*- coding: utf-8 -*-

"""Module for creating ``@type [bridge-]server-descriptor``s.

.. authors:: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
             Matthew Finkel <sysrqb@torproject.org>
.. licence:: see LICENSE file for licensing details
.. copyright:: (c) 2013-2014 The Tor Project, Inc.
               (c) 2013-2014 Isis Lovecruft
               (c) 2013-2014 Matthew Finkel
"""

import math
import random

from leekspin import crypto
from leekspin import torversions


def makeProtocolsLine(version=None):
    """Generate an appropriate [bridge-]server-descriptor 'protocols' line.

    :param str version: One of ``SERVER_VERSIONS``.
    :rtype: str
    :returns: An '@type [bridge-]server-descriptor' 'protocols' line.
    """
    line = ''
    if (version is not None) and torversions.shouldHaveOptPrefix(version):
        line += 'opt '
    line += 'protocols Link 1 2 Circuit 1'
    return line

def makeExtraInfoDigestLine(hexdigest, version):
    """Create a line to embed the hex SHA-1 digest of the extrainfo.

    :param string hexdigest: Should be the hex-encoded (uppercase) output of
        the SHA-1 digest of the generated extrainfo document (this is the
        extra-info descriptor, just without the signature at the end). This is
        the same exact digest which gets signed by the OR server identity key,
        and that signature is appended to the extrainfo document to create the
        extra-info descriptor.
    :param string version: One of ``SERVER_VERSIONS``.
    :rtype: string
    :returns: An ``@type [bridge-]server-descriptor`` 'extra-info-digest'
        line.
    """
    line = ''
    if (version is not None) and torversions.shouldHaveOptPrefix(version):
        line += 'opt '
    line += 'extra-info-digest %s' % hexdigest
    return line

def makeFingerprintLine(fingerprint, version=None):
    """Generate an appropriate [bridge-]server-descriptor 'fingerprint' line.

    For example, for tor-0.2.3.25 and prior versions, this would look like:
      |
      | opt fingerprint D4BB C339 2560 1B7F 226E 133B A85F 72AF E734 0B29
      |

    :param string fingerprint: A public key fingerprint in groups of four,
         separated by spaces.
    :param string version: One of ``SERVER_VERSIONS``.
    :rtype: string
    :returns: An '@type [bridge-]server-descriptor' 'published' line.
    """
    line = ''
    if (version is not None) and torversions.shouldHaveOptPrefix(version):
        line += 'opt '
    line += 'fingerprint %s' % crypto.convertToSpaceyFingerprint(fingerprint)
    return line

def makeBandwidthLine(variance=30):
    """Create a random 'bandwidth' line with some plausible burst variance.

    From torspec.git/dir-spec.txt, §2.1 "Router descriptors":
      | "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed NL
      |
      | [Exactly once]
      |
      |   Estimated bandwidth for this router, in bytes per second.  The
      |   "average" bandwidth is the volume per second that the OR is willing
      |   to sustain over long periods; the "burst" bandwidth is the volume
      |   that the OR is willing to sustain in very short intervals.  The
      |   "observed" value is an estimate of the capacity this relay can
      |   handle.  The relay remembers the max bandwidth sustained output over
      |   any ten second period in the past day, and another sustained input.
      |   The "observed" value is the lesser of these two numbers.

    The "observed" bandwidth, in this function, is taken as some random value,
    bounded between 20KB/s and 2MB/s. For example, say:

    >>> import math
    >>> variance = 25
    >>> observed = 180376
    >>> percentage = float(variance) / 100.
    >>> percentage
    0.25

    The ``variance`` in this context is the percentage of the "observed"
    bandwidth, which will be added to the "observed" bandwidth, and becomes
    the value for the "burst" bandwidth:

    >>> burst = observed + math.ceil(observed * percentage)
    >>> assert burst > observed

    This doesn't do much, since the "burst" bandwidth in a real
    [bridge-]server-descriptor is reported by the OR; this function mostly
    serves to avoid generating completely-crazy, totally-implausible bandwidth
    values. The "average" bandwidth value is then just the mean value of the
    other two.

    :param integer variance: The percent of the fake "observed" bandwidth to
        increase the "burst" bandwidth by.
    :rtype: string
    :returns: A "bandwidth" line for a [bridge-]server-descriptor.
    """
    observed = random.randint(20 * 2**10, 2 * 2**30)
    percentage = float(variance) / 100.
    burst = int(observed + math.ceil(observed * percentage))
    bandwidths = [burst, observed]
    nitems = len(bandwidths) if (len(bandwidths) > 0) else float('nan')
    avg = int(math.ceil(float(sum(bandwidths)) / nitems))
    line = "bandwidth %s %s %s" % (avg, burst, observed)
    return line

def makeHSDirLine(version):
    """This line doesn't do much… all the cool kids are HSDirs these days.

    :param string version: One of ``SERVER_VERSIONS``.
    :rtype: string
    :returns: An ``@type [bridge-]server-descriptor`` 'hidden-service-dir'
        line.
    """
    line = ''
    if (version is not None) and torversions.shouldHaveOptPrefix(version):
        line += 'opt '
    line += 'hidden-service-dir'
    return line
