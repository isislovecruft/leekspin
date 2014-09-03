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

.PHONY: install test
.DEFAULT: install test

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

clean: clean-build clean-dist

clean-all: clean-emacs clean-pyc clean-build clean-dist

coverage:
	-coverage -rcfile=".coveragerc" run $(which trial) ./leekspin/test/test_* && \
		coverage report && coverage html
	-firefox coverage-html/index.html

upload: clean-all
	torsocks python setup.py bdist_egg upload --sign
	#torsocks python setup.py bdist_wheel upload --sign
	torsocks python setup.py sdist upload --sign
