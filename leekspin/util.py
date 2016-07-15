# -*- coding: utf-8 -*-

"""Common general utilities."""

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

    otherargs   = parser.add_mutually_exclusive_group()
    infoargs = otherargs.add_mutually_exclusive_group()
    infoargs.add_argument("-v", "--verbose", action="store_true",
                          help="print information to stdout")
    infoargs.add_argument("-q", "--quiet", action="store_true",
                          help="don't print anything")

    versionargs = parser.add_mutually_exclusive_group()
    versionargs.add_argument("--version", action="store_true",
                             help="print leekspin version and exit")

    descgroup = parser.add_argument_group()
    descgroup.title = "descriptor types"
    descgroup.argument_default = "--bridge"
    descgroup1 = descgroup.add_mutually_exclusive_group()
    descgroup1.add_argument("-r", "--relay", action="store_true",
                            help="generate relay descriptors")
    descgroup1.add_argument("-b", "--bridge", action="store_true",
                            help="generate bridge descriptors")
    descgroup1.add_argument("-hs", "--hidden-service", action="store_true",
                            help="generate HS rendezvous descriptors")
    descgroup1.set_defaults(relay=False, bridge=True, hidden_service=False)

    descgroup2 = parser.add_argument_group()
    descgroup2.title = "descriptor variations"
    descgroup2.add_argument("-xt", "--without-tap", action="store_true",
                            help=("generate descriptors without TAP support, "
                                  "e.g. without RSA keys"))
    descgroup2.add_argument("-xn", "--without-ntor", action="store_true",
                            help=("generate descriptors without ntor support, "
                                  "e.g. without Ed25519 keys"))
    descgroup2.set_defaults(without_tap=False, without_ntor=False)

    group = parser.add_argument_group()
    group.title = "required arguments"
    group.add_argument("-n", "--descriptors", default=0,
                       help="generate <n> descriptor sets", type=int)

    return parser

def _checkIPValidity(ip):
    """Check that an IP address is valid.

    :type ip: ``ipaddr.IPAddress``
    :param ip: The ip address to check.
    """
    if (ip.is_link_local or
        ip.is_loopback or
        ip.is_multicast or
        ip.is_private or
        ip.is_unspecified or
        ((ip.version == 6) and ip.is_site_local) or
        ((ip.version == 4) and ip.is_reserved)):
        return False
    return True

def randomIP():
    """Create a random IPv4 or IPv6 address."""
    maybe = int(random.getrandbits(1))
    ip = randomIPv4() if maybe else randomIPv6()
    return ip

def randomIPv4():
    """Create a random IPv4 address."""
    validIP = None
    while not validIP:
        maybe = ipaddr.IPv4Address(random.getrandbits(32))
        valid = _checkIPValidity(maybe)
        if valid:
            validIP = maybe
            break
    return validIP

def randomIPv6():
    """Create a random IPv6 address."""
    validIP = None
    while not validIP:
        maybe = ipaddr.IPv6Address(random.getrandbits(128))
        valid = _checkIPValidity(maybe)
        if valid:
            validIP = maybe
            break
    return validIP

def randomPort():
    """Get a random integer in the range ``[1026, 65530]``.

    The reason that port 1025 is missing is because the IPv6 port (in the
    ``or-address``/``a`` lines), if there will be one, will be whatever the
    random ORPort is, minus one.

    The pluggable transport in the extrainfo descriptor (if there are any) are
    calculated as the random ORPort, plus some.

    :rtype: int
    """
    return random.randint(1026, 65530)

def getHexString(size):
    """Get a capitalised hexidecimal string **size** bytes long.

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
        timestamp for (and to consider as the maximum time, if other options
        are enabled).
    :param str fmt: A strftime(3) format string for the timestamp. If not
        given, defaults to ISO-8601 format without the ``'T'`` separator.
    :param bool variation: If True, enable timestamp variation. Otherwise,
        make all timestamps be set to the current time.
    :type period: int or None
    :param period: If given, vary the generated timestamps to be a random time
        between **period** hours ago and the current time. If ``None``,
        generate completely random timestamps which are anywhere between the
        Unix Epoch and the current time. This parameter only has an effect if
        **variation** is enabled.
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
    """Open **filename** and write a string containing **descriptors** into it.

    :param str filename: The name of the file to write to.
    :param str descriptors: A giant string containing descriptors,
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
