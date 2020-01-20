# -*- coding: utf-8 -*-
"""
File: passphrase.py
Description: Tasks related to passphrases, such as generating one.

Author: E. Chris Pedro
Created: 2020-01-20


This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
"""

from passwd import diceware8k
from random import SystemRandom


def generate(length):
    """Generate passphrase of a given length. This code uses the Diceware 8K
    word list downloaded from http://world.std.com/%7Ereinhold/diceware.html
    """
    if length < 4:
        raise ValueError('Passphrases should be 4 or more in length.')
        return 1

    passphrase = ''
    gen = SystemRandom()
    for i in range(length):
        if i != 0:
            passphrase += ' '
        passphrase += '{}'.format(gen.choice(diceware8k.DICEWARE8K_WORDS))

    return passphrase


