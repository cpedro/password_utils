#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: is_it_pwned.py
Description: Checks a password against the Have I Been Pwned database, and
  reports back on whether or not it has been listed.  For more info on the
  API docs, see https://haveibeenpwned.com/API/v2

usage: is_it_pwned.py [-h] [passwords [passwords ...]]

Generate Shadow Hashes.

positional arguments:
  passwords   Password to lookup.

optional arguments:
  -h, --help  show this help message and exit

Author: E. Chris Pedro
Created: 2019-12-24


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
import sys
import getpass

from passwd import pwned_passwords as pwned
from signal import signal, SIGINT


def lookup_password(passwd):
    """Used API to lookup password and print result.
    """
    status = 0
    passwd = passwd.strip()

    try:
        sha1, count = pwned.lookup(passwd)
        if count:
            msg = '{0} has been pwned {1} times (hash: {2})'
            print(msg.format(passwd, count, sha1))
            status = 1
        else:
            print('That password has not been pwned.')
    except UnicodeError:
        errormsg = sys.exc_info()[1]
        print('Password could not be checked: {0}'.format(errormsg))
        status = 1

    return status


def parse_args(args):
    """Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description='Check if passwords have been'
                                                 ' comprised')
    parser.add_argument('password', nargs='*',
                        help='Password to lookup.')

    return parser.parse_args(args)


def handler(signal_received, frame):
    """Signal handler.
    """
    sys.exit(0)


def main(args):
    """Main method.
    """
    status = 0

    args = parse_args(args)
    if sys.stdin.isatty() and len(args.password) == 0:
        try:
            status = lookup_password(getpass.getpass('Password to check: '))
        # Catch Ctrl-D
        except EOFError:
            return status
    else:
        for passwd in args.password or sys.stdin:
            status = lookup_password(passwd)

    return status


if __name__ == '__main__':
    signal(SIGINT, handler)
    sys.exit(main(sys.argv[1:]))


