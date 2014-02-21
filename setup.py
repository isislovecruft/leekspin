#!/usr/bin/env python
#_____________________________________________________________________________
#
# This file is part of LeekSpin, an Onion Router descriptor generator.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function

import os
import setuptools
import sys

from glob import glob

# setup automatic versioning (see top-level versioneer.py file):
import versioneer
versioneer.versionfile_source = 'leekspin/_version.py'
versioneer.versionfile_build = 'leekspin/_version.py'

# when creating a release, tags should be prefixed with 'leekspin-', like so:
#
#     git checkout -b release-6.6.6 develop
#     [do some stuff, merge whatever, test things]
#     git tag -S leekspin-6.6.6
#     git push tpo-common --tags
#     git checkout master
#     git merge -S --no-ff release-6.6.6
#     git checkout develop
#     git merge -S --no-ff master
#     git branch -d release-6.6.6
#
versioneer.tag_prefix = 'leekspin-'
# source tarballs should unpack to a directory like 'leekspin-6.6.6'
versioneer.parentdir_prefix = 'leekspin-'


def get_cmdclass():
    """Get our cmdclass dictionary for use in setuptool.setup().

    This must be done outside the call to setuptools.setup() because we need
    to add our own classes to the cmdclass dictionary, and then update that
    dictionary with the one returned from versioneer.get_cmdclass().
    """
    cmdclass = {'test': runTests}
    cmdclass.update(versioneer.get_cmdclass())
    return cmdclass

def get_requirements():
    """Extract the list of requirements from our requirements.txt.

    :rtype: 2-tuple
    :returns: Two lists, the first is a list of requirements in the form of
        pkgname==version. The second is a list of URIs or VCS checkout strings
        which specify the dependency links for obtaining a copy of the
        requirement.
    """
    requirements_file = os.path.join(os.getcwd(), 'requirements.txt')
    requirements = []
    links=[]
    try:
        with open(requirements_file) as reqfile:
            for line in reqfile.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                elif line.startswith(
                        ('https://', 'git://', 'hg://', 'svn://')):
                    links.append(line)
                else:
                    requirements.append(line)

    except (IOError, OSError) as error:
        print(error)

    return requirements, links

class runTests(setuptools.Command):
    # Based on setup.py from mixminion, which is based on setup.py
    # from Zooko's pyutil package, which is in turn based on
    # http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html
    description = "Run unit tests"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path[:]
        sys.path[0:0] = [self.build_purelib, self.build_platlib]
        try:
            testmod = __import__("leekspin.test", globals(), "", [])
            testmod.Tests.main()
        finally:
            sys.path = old_path

#requires, deplinks = get_requirements()

setuptools.setup(
    name='leekspin',
    version=versioneer.get_version(),
    description='An Onion Router descriptor generator',
    author='isis & sysrqb',
    author_email='isis@torproject.org',
    maintainer='isis',
    maintainer_email='isis@torproject.org 0xA3ADB67A2CDB8B35',
    url='https://www.torproject.org',
    download_url='https://gitweb.torproject.org/user/isis/leekspin.git',
    packages=['leekspin'],
    scripts=['scripts/generate-OR-descriptors'],
    extras_require={'ntor': ["nacl==0.1.0"],
                    'test': ["sure==0.4.5", "coverage==3.6"]},
    zip_safe=False,
    cmdclass=get_cmdclass(),
    #include_package_data=True,
    #install_requires=requires,
    #dependency_links=deplinks,
)
