# -*- coding: utf-8 -*-

"""Parsers for Tor version numbers.

Portions of this module are directly taken from, or derived from,
:api:`twisted.python.compat`, and are subject to the Twisted Matrix Labs
copyright and license, in addition to the copyrights and license for the rest
of this program.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import random
import sys


#: The <major>.<minor>.<micro>.<rev> version numbers for tor, taken from the
#: 'server-versions' line of a consensus file
SERVER_VERSIONS = ['0.2.2.39',
                   '0.2.3.24-rc',
                   '0.2.3.25',
                   '0.2.4.5-alpha',
                   '0.2.4.6-alpha',
                   '0.2.4.7-alpha',
                   '0.2.4.8-alpha',
                   '0.2.4.9-alpha',
                   '0.2.4.10-alpha',
                   '0.2.4.11-alpha',
                   '0.2.4.12-alpha',
                   '0.2.4.14-alpha',
                   '0.2.4.15-rc',
                   '0.2.4.16-rc',
                   '0.2.4.17-rc',
                   '0.2.4.18-rc',
                   '0.2.4.19',
                   '0.2.4.20',
                   '0.2.5.1-alpha',
                   ]

if sys.version_info < (3, 0):
    _PY3 = False
else:
    _PY3 = True


class IncomparableVersions(TypeError):
    """Two versions could not be compared."""

class InvalidVersion(ValueError):
    """Invalid version string."""


def _comparable(klass):
    """Class decorator that ensures support for the special :meth:`__cmp__` method.

    On Python 2 this does nothing.

    On Python 3, :meth:`__eq__`, :meth:`__lt__`, etc. methods are added to the
    class, relying on :meth:`__cmp__` to implement their comparisons.
    """
    # On Python 2, __cmp__ will just work, so no need to add extra methods:
    if not _PY3:
        return klass

    def __eq__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c == 0

    def __ne__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c != 0

    def __lt__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c < 0

    def __le__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c <= 0

    def __gt__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c > 0

    def __ge__(self, other):
        c = self.__cmp__(other)
        if c is NotImplemented:
            return c
        return c >= 0

    klass.__lt__ = __lt__
    klass.__gt__ = __gt__
    klass.__le__ = __le__
    klass.__ge__ = __ge__
    klass.__eq__ = __eq__
    klass.__ne__ = __ne__
    return klass

def getRandomVersion():
    """Get a random Tor version from ``server-versions`` in the consensus.

    :rtype: str
    :returns: One of :data:`SERVER_VERSIONS`.
    """
    vers = random.choice(SERVER_VERSIONS)
    return vers

def shouldHaveOptPrefix(version):
    """Returns true if descriptor lines for a Tor **version** should be prefixed
    with ``'opt '``.

    In tor, up to and including, version 0.2.3.25, server-descriptors (bridge
    or relay) prefixed several lines with ``'opt '``. For the 0.2.3.x
    series, these lines were:

     - ``protocols``
     - ``fingerprint``
     - ``hidden-service-dir``
     - ``extra-info-digest``

    :param str version: One of :data:`SERVER_VERSIONS`.
    :rtype: bool
    :returns: ``True`` if we should include the ``'opt '`` prefix; ``False``
        otherwise.
    """
    changed_in  = Version('0.2.4.1-alpha', package='tor')
    our_version = Version(version, package='tor')
    if our_version < changed_in:
        return True
    return False

def shouldSupportHSIntroV0(version):
    """Returns true if a Hidden Service is old enough to support the Hidden
    Service intro protocol version 0.

    See :func:`~leekspin.rendezvous.generateProtocolVersionsLine`.

    :param str version: One of :data:`SERVER_VERSIONS`.
    :rtype: bool
    :returns: ``True`` if we should include the intro protocol version 0;
        ``False`` otherwise.
    """
    changed_in  = Version('0.2.0.7-alpha', package='tor')
    our_version = Version(version, package='tor')
    if our_version < changed_in:
        return True
    return False

@_comparable
class _inf(object):
    """An object that is ∞ bigger than all other objects."""
    def __cmp__(self, other):
        """Compare another object with this infinite one.

        If the other object is infinite, it wins. Otherwise, this class is
        always the winner.

        :param other: Another object.
        :rtype: int
        :returns: 0 if other is inf, 1 otherwise.
        """
        if other is _inf:
            return 0
        return 1

_inf = _inf()


@_comparable
class Version(object):
    """Holds, parses, and does comparison operations for version numbers.

    :attr str major: The major version number.
    :attr str minor: The minor version number.
    :attr str micro: The micro version number.
    :attr str prerelease: Sometimes another number, or ``alpha``/``rc2``/etc.,
         often suffixed with a ``-``, ``+``, or ``#``.
    """
    def __init__(self, version, package=None):
        """Create a version object.

        Comparisons may be computed between instances of :class:`Version`.

        .. note:: This class was modified from the original Twisted class
            (:api:`twisted.python.versions.Version`) because Tor's versioning
            system uses four integers, separated by ``.``, so that the
            ``prerelease`` attribute, and all methods using it, can accomodate
            for the idiosyncracies in Tor's version strings.  The standard
            ``<major>.<minor>.<micro>-<prerelease>`` version format will also
            work just the same as it does with the unmodified Twisted class.

        >>> ver = torversions.Version('0.2.5.1-alpha', 'tor')
        >>> ver.base
        0.2.5.1-alpha
        >>> str(ver)
        tor-0.2.5.1-alpha
        >>> ver.micro
        5
        >>> ver.prerelease
        1-alpha
        >>> ver.package
        tor


        :param string version: One of :data:`SERVER_VERSIONS`.
        :param string package: The package or program which we are creating a
             version number for, i.e. for ``"tor-0.2.5.1-alpha"`` the
             **package** would be ``"tor"``.
        """
        if version.find('.') == -1:
            raise InvalidVersion("%r isn't a valid version string!" % version)

        self.major = ''
        self.minor = ''
        self.micro = ''
        self.prerelease = ''

        components = version.split('.')
        if len(components) > 0:
            try:
                self.prerelease = components.pop()
                self.micro      = components.pop()
                self.minor      = components.pop()
                self.major      = components.pop()
            except IndexError:
                pass

        self.package = package if package is not None else ''

    def base(self):
        """Get the base version number (with prerelease).

        :rtype: str
        :returns: A version number, without the package/program name, and with
             the :attr:`prefix` (if available). For example:
             ``"0.2.5.1-alpha"``.
        """
        baseVersion = '%d.%d.%d%s' % (self.major, self.minor, self.micro,
                                      self.getPrefixedPrerelease())
        return baseVersion

    def getPrefixedPrerelease(self, separator='.'):
        """Get the prerelease string, prefixed by the separator :attr:`prefix`.

        :param str separator: The separator to use between the rest of the
             version string and the **prerelease** string.
        :rtype: str
        :returns: The **separator** plus the :attr:`prefix`, for example
            ``".1-alpha"``.
        """
        prefixed = ''
        if self.prerelease is not None:
            prefixed = separator + self.prerelease
        return pre

    def __repr__(self):
        prerelease = getPrefixedPrerelease('')
        return '%s(package=%r, major=%d, minor=%d, micro=%d, prerelease=%s)' \
            % (self.__class__.__name__, str(self.package),
               self.major, self.minor, self.micro, self.prerelease)

    def __str__(self):
        """Return the package name and version in string form, i.e.
        ``"tor-0.2.24"``.
        """
        if self.package:
            versionstr = str(self.package) + '-'
        versionstr += self.base()
        return versionstr

    def __cmp__(self, other):
        """Compare two versions, considering major versions, minor versions,
        micro versions, then prereleases.

        A version with a prerelease is always less than a version without a
        prerelease. If both versions have prereleases, they will be included
        in the comparison.

        :type other: :class:`Version`
        :param other: Another version.
        :raise IncomparableVersions: When the package names of the versions
            differ.
        :rtype: int
        :returns: :exc:`exceptions.NotImplemented` when the other object is
            not a :class:`Version`.  Otherwise one of ``-1``, ``0``, or ``1``.
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.package != other.package:
            raise IncomparableVersions("%r != %r"
                                       % (self.package, other.package))

        if self.prerelease is None:
            prerelease = _inf
        else:
            prerelease = self.prerelease

        if other.prerelease is None:
            otherpre = _inf
        else:
            otherpre = other.prerelease

        x = cmp((self.major,
                    self.minor,
                    self.micro,
                    prerelease),
                   (other.major,
                    other.minor,
                    other.micro,
                    otherpre))
        return x
