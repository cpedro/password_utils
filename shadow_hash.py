#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: shadow_hash.py
Description: A simple python script that can be used to generate a password
hash that can be inserted directly into the `/etc/shadow` file on a Linux or
Unix system.

usage: shadow_hash.py [-h] [-m {SHA512,SHA256,MD5}]
                      [passwords [passwords ...]]

Generate Shadow Hashes.

positional arguments:
  passwords             Password to generate hashes for.

optional arguments:
  -h, --help            show this help message and exit
  -m {SHA512,SHA256,MD5}, --method {SHA512,SHA256,MD5}
                        Hashing method to use, default is SHA512

Author: E. Chris Pedro
Created: 2019-12-27


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

import argparse
import getpass
import sys

from passwd import shadow
from signal import signal, SIGINT


def parse_args(args):
    """Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description='Generate Shadow Hashes')
    parser.add_argument('-m', '--method', default='SHA512',
                        choices=shadow.HASH_METHODS,
                        help='Hashing method to use, default is SHA512')
    parser.add_argument('password', nargs='*',
                        help='Password to generate hashes for.')

    return parser.parse_args(args)


def handler(signal_received, frame):
    """Signal handler.
    """
    sys.exit(0)


def main(args):
    """Main method.
    """
    args = parse_args(args)
    if sys.stdin.isatty() and len(args.password) == 0:
        passwd1, passwd2 = None, ''

        while passwd1 != passwd2:
            try:
                passwd1 = getpass.getpass('Enter password: ')
                passwd2 = getpass.getpass('Re-enter password: ')
            # Catch Ctrl-D
            except EOFError:
                return 0

            if passwd1 != passwd2:
                print('Passwords entered do not match. Try again.')

        print(shadow.generate_hash(passwd1, args.method))
    else:
        for passwd in args.password or sys.stdin:
            print(shadow.generate_hash(passwd, args.method))

    return 0


if __name__ == '__main__':
    signal(SIGINT, handler)
    sys.exit(main(sys.argv[1:]))


