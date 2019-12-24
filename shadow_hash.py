#!/usr/bin/env python3
"""
File: shadow_hash.py
Description: A simple python script that can be used to generate a password hash
that can be inserted directly into the `/etc/shadow` file on a Linux or Unix
system.

Author: E. Chris Pedro
Version: 2019-12-24

Current supported hash methods (from most secure to least):
    * SHA512 (Default)
    * SHA256
    * MD5

usage: shadow_hash.py [-h] [-m {SHA512,SHA256,MD5}]
                      [passwords [passwords ...]]

Generate Shadow Hashes.

positional arguments:
  passwords             Password to generate hashes for.

optional arguments:
  -h, --help            show this help message and exit
  -m {SHA512,SHA256,MD5}, --method {SHA512,SHA256,MD5}
                        Hashing method to use, default is SHA512


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
import crypt
import getpass
import sys

from signal import signal, SIGINT


# Change this dictionary to change supported hash methods.
hashes = {
    'SHA512': crypt.METHOD_SHA512,
    'SHA256': crypt.METHOD_SHA256,
    'MD5':    crypt.METHOD_MD5,
}

def print_shadow(passwd, method):
    status = 0

    global hashes
    passwd = passwd.strip()

    try:
        print(crypt.crypt(passwd, crypt.mksalt(hashes[method.upper()])))
    except KeyError as error:
        print('Hash method {} not supported.'.format(method))
        status = 1
    except Exception as exception:
        print(str(exception))
        status = 1

    return status


def parse_args(args):
    parser = argparse.ArgumentParser(description='Generate Shadow Hashes.')
    parser.add_argument('-m', '--method', default='SHA512', choices=hashes,
        help='Hashing method to use, default is SHA512')
    parser.add_argument('password', nargs='*',
        help='Password to generate hashes for.')

    return parser.parse_args(args)

def main(args):
    status = 0

    args = parse_args(args)
    if sys.stdin.isatty() and len(args.password) == 0:
        try:
            passwd1 = getpass.getpass('Enter password: ')
            passwd2 = getpass.getpass('Re-enter password: ')
        # Catch Ctrl-D
        except EOFError as error:
            return status

        if passwd1 == passwd2:
            status = print_shadow(passwd1, args.method)
        else:
            print('Passwords entered do not match.')
            status = 1
    else:
        for passwd in args.password or sys.stdin:
            status = print_shadow(passwd, args.method)

    return status


def handler(signal_received, frame):
    sys.exit(0)


if __name__ == '__main__':
    signal(SIGINT, handler)
    sys.exit(main(sys.argv[1:]))


