# -*- coding: utf-8 -*-

"""util - common utilities
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from codecs import open as open

import argparse
import ipaddr
import random
import sys
import time

from leekspin import __version__
from leekspin import __package__


def getArgParser():
    """Get our :class:`~argparse.ArgumentParser`."""
    version_ = '-'.join([__package__, __version__.rsplit('_', 1)[0]])
    parser = argparse.ArgumentParser(prog=__package__,
                                     add_help=True)
    # Otherwise we hit an argparse bug that prints the following cryptic error:
    # `'Namespace' object has no 'version' attribute`
    parser.prog = __package__
    parser.version = version_
    parser.description  = "Generate a signed set of network-status, "
    parser.description += "extra-info, and server descriptor documents "
    parser.description += "for mock Tor relays or bridges."
    verbargs = parser.add_mutually_exclusive_group()
    infoargs = parser.add_mutually_exclusive_group()
    infoargs.add_argument("-v", "--verbose", action="store_true",
                          help="print information to stdout")
    infoargs.add_argument("-q", "--quiet", action="store_true",
                          help="don't print anything")
    verbargs.add_argument("--version", action="store_true",
                          help="print leekspin version and exit")

    group = parser.add_argument_group()
    group.title = "required arguments"
    group.add_argument("-n", "--descriptors", default=0,
                       help="generate <n> descriptor sets", type=int)
    return parser

def randomIP():
    """Create a random IPv4 or IPv6 address."""
    maybe = int(random.getrandbits(1))
    ip = randomIPv4() if maybe else randomIPv6()
    return ip

def randomIPv4():
    """Create a random IPv4 address."""
    return ipaddr.IPv4Address(random.getrandbits(32))

def randomIPv6():
    """Create a random IPv6 address."""
    return ipaddr.IPv6Address(random.getrandbits(128))

def randomPort():
    """Get a random integer in the range [1024, 65535]."""
    return random.randint(1025, 65535)

def getHexString(size):
    """Get a capitalised hexidecimal string ``size`` bytes long.

    :param int size: The number of bytes in the returned string.
    :rtype: str
    :returns: A hex string.
    """
    hexstr = ""
    for _ in xrange(size):
        hexstr += random.choice("ABCDEF0123456789")
    return hexstr

def makeTimeStamp(now=None, fmt=None, variation=False, period=None):
    """Get a random timestamp suitable for a bridge server descriptor.

    :param int now: The time, in seconds since the Epoch, to generate the
                    timestamp for (and to consider as the maximum time, if
                    other options are enabled).
    :param str fmt: A strftime(3) format string for the timestamp. If not
                    given, defaults to ISO-8601 format without the 'T'
                    separator.
    :param bool variation: If True, enable timestamp variation. Otherwise,
                           make all timestamps be set to the current time.
                           (default: False)
    :type period: int or None
    :param period: If given, vary the generated timestamps to be a random time
                   between **period** hours ago and the current time. If
                   ``None``, generate completely random timestamps which are
                   anywhere between the Unix Epoch and the current time. This
                   parameter only has an effect if ``variation`` is enabled.
    """
    now = int(now) if now is not None else int(time.time())
    fmt = fmt if fmt else "%Y-%m-%d %H:%M:%S"

    if variation:
        then = 1
        if period is not None:
            secs = int(period) * 3600
            then = now - secs
        # Get a random number between one epochseconds number and another
        diff = random.randint(then, now)
        # Then rewind the clock
        now = diff

    return time.strftime(fmt, time.localtime(now))

def writeDescToFile(filename, descriptors):
    """Open ``filename`` and write a string containing descriptors into it.

    :param string filename: The name of the file to write to.
    :param string descriptors: A giant string containing descriptors,
        newlines, formatting, whatever is necessary to make it look like a
        file tor would generate.
    """
    encoding = sys.getfilesystemencoding()
    descript = descriptors.encode(encoding, 'replace')
    try:
        with open(filename, 'wb', encoding=encoding, errors='replace') as fh:
            fh.write(descript)
            fh.flush()
    except (IOError, OSError) as err:
        print("Failure while attempting to write descriptors to file '%s': %s"
              % (filename, err.message))
