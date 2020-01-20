#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: is_it_pwned.py
Description: Checks a password against the Have I Been Pwned database, and
  reports back on whether or not it has been listed.  For more info on the
  API docs, see https://haveibeenpwned.com/API/v2

Author: E. Chris Pedro
Version: 2019-12-24

usage: is_it_pwned.py [-h] [passwords [passwords ...]]

Generate Shadow Hashes.

positional arguments:
  passwords   Password to lookup.

optional arguments:
  -h, --help  show this help message and exit


Some code taken from Mike Pound's script that does the same.  Mike's script
can be found here: <https://github.com/mikepound/pwned-search>


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
import hashlib

from signal import signal, SIGINT

try:
    import requests
except ModuleNotFoundError:
    print('run: "pip3 install requests"')
    raise


def pwned_api_lookup(passwd):
    # Change if API endpoint changes.
    api_url = 'https://api.pwnedpasswords.com/range/'

    sha1 = hashlib.sha1(passwd.encode('utf-8')).hexdigest().upper()
    head, tail = sha1[:5], sha1[5:]

    url = api_url + format(head)
    req = requests.get(url)
    status_code = req.status_code
    if status_code != 200:
        raise RuntimeError('Error fetching "{}": {}'.format(url, status_code))

    hashes = (line.split(':') for line in req.text.splitlines())
    count = next((int(count) for val, count in hashes if val == tail), 0)
    return sha1, count


def lookup_password(passwd):
    status = 0
    passwd = passwd.strip()

    try:
        sha1, count = pwned_api_lookup(passwd)
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
    parser = argparse.ArgumentParser(description='Check if passwords have been'
                                                 ' comprised')
    parser.add_argument('password', nargs='*',
                        help='Password to lookup.')

    return parser.parse_args(args)


def handler(signal_received, frame):
    sys.exit(0)


def main(args):
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


