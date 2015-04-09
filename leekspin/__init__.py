#_____________________________________________________________________________
#
# This file is part of LeekSpin, an Onion Router descriptor generator.
#
# :authors: Isis Lovecruft <isis@torproject.org>   0xA3ADB67A2CDB8B35
#           Matthew Finkel <sysrqb@torproject.org> 0x017DD169EA793BE2
# :copyright: (c) 2013-2015, The Tor Project, Inc.
#             (c) 2013-2015, all entities within the AUTHORS file
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

__package__ = 'leekspin'

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
