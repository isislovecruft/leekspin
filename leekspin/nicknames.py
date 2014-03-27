# -*- coding: utf-8 -*-

"""Onion Router nickname generator for making descriptors easily searchable.

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

from codecs import open as open

import logging
import os
import random
import string

logging.getLogger('leekspin')


DICTIONARY_FILE          = '/usr/share/dict/words'
NICKNAME_LENGTH_MAX      = 19
NICKNAME_LENGTH_MIN      = 1
NICKNAME_LENGTH_PREF_MIN = 10


def _createWordsForNicks():
    """Create a list of words used to generate random OR nicknames."""
    allowedChars = string.letters + string.digits
    wordlist = []
    if os.path.isfile(DICTIONARY_FILE) and os.access(DICTIONARY_FILE, os.R_OK):
        try:
            dictfh = open(DICTIONARY_FILE)
            rawdict = dictfh.readlines()
        except (OSError, IOError):
            logging.error("error opening dictionary")
            return []

        for word in rawdict:
            for char in word:
                if char not in allowedChars:
                    word = word.replace(char, str()).capitalize()
            wordlist.append(word)
    return wordlist


_words = _createWordsForNicks()

MAX_INDEX_WORDS = len(_words) - 1


def _checkWordLength(word, minlength=NICKNAME_LENGTH_MIN, maxlength=NICKNAME_LENGTH_MAX):
    """Returns ``True`` if **word** is an acceptable length."""
    if (int(minlength) < 0) or (int(maxlength) <= 0):
        return False
    if (int(minlength) <= len(str(word)) <= maxlength):
        return True
    return False

def _getCharsNeeded(word, minlength, maxlength):
    minNeeded  = minlength - len(str(word))
    maxNeeded  = maxlength - len(str(word))
    return minNeeded, maxNeeded

def _getRandomWord(minlength=NICKNAME_LENGTH_MIN, maxlength=NICKNAME_LENGTH_MAX):
    pick = lambda: _words[random.randint(0, MAX_INDEX_WORDS)]
    picked = pick()

    while not _checkWordLength(picked, minlength, maxlength):
        picked = pick()
    return picked

def generateNickname(maxlength=NICKNAME_LENGTH_MAX):
    """Generate a random alphanumeric nickname conforming to the specified length."""
    if len(_words) == 0:  # if there was no /usr/share/dict/words file
        return "Unnamed"

    nickname = _getRandomWord(NICKNAME_LENGTH_MIN, maxlength)
    minNeeded, maxNeeded = _getCharsNeeded(nickname, NICKNAME_LENGTH_PREF_MIN, maxlength)

    while minNeeded > 0:
        nickname += _getRandomWord(minNeeded, maxNeeded)
        minNeeded, maxNeeded = _getCharsNeeded(nickname, minNeeded, maxNeeded)
    else:
        logging.info("%s (length: %d)" % (nickname, len(nickname)))
        return nickname
