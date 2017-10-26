#_____________________________________________________________________________
#
# This file is part of LeekSpin, an Onion Router descriptor generator.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

.PHONY: install test
.DEFAULT: install test

VERSION:=$(shell git describe)
GNUPG:=$(shell which gpg2)

all:
	python setup.py build

test:
	python setup.py test

pep8:
	-find leekspin/*.py | xargs pep8

pylint:
	-pylint --rcfile=./.pylintrc ./leekspin/

pyflakes:
	-pyflakes leekspin/

install:
	python setup.py install --record installed-files.txt

force-install:
	python setup.py install --force --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
	rm installed-files.txt

reinstall: uninstall force-install

docs:
	python setup.py build_sphinx --version "$(VERSION)"
	cd build/sphinx/html && \
		zip -r ../"$(VERSION)"-docs.zip ./ && \
		echo "Your package documents are in build/sphinx/$(VERSION)-docs.zip"

clean-emacs:
	find . -name '*~' -delete
	-find . -name '\.#*' -exec rm -i {} \;

clean-pyc:
	find . -name '*.pyc' -delete

clean-build:
	-rm -rf build
	-rm -rf leekspin.egg-info
	-rm -rf MANIFEST

clean-dist:
	-rm -rf dist

clean-descriptors:
	-rm bridge-descriptors
	-rm cached-extrainfo
	-rm cached-extrainfo.new
	-rm networkstatus-bridges
	-rm cached-consensus
	-rm cached-descriptors
	-rm rendezvous-service-descriptors

clean: clean-build clean-dist clean-descriptors

clean-all: clean-emacs clean-pyc clean-build clean-dist

coverage:
	-coverage -rcfile=".coveragerc" run $(which trial) ./leekspin/test/test_* && \
		coverage report && coverage html
	-firefox coverage-html/index.html

upload: clean-all
	python setup.py bdist_egg
	#python setup.py bdist_wheel
	python setup.py sdist --formats=gztar,zip
	twine upload --sign --sign-with "$(GNUPG)" --skip-existing dist/*
