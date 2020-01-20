# -*- coding: utf-8 -*-
"""
File: pwned_password.py
Description: Tasks related to API calls to pwnedpasswords.com. For more info on
the API docs, see https://haveibeenpwned.com/API/v2

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

import hashlib

try:
    import requests
except ModuleNotFoundError:
    print('run: "pip3 install requests"')
    raise

""" Change if API endpoint changes. """
API_URL = 'https://api.pwnedpasswords.com/range/'


def lookup(passwd):
    """Perform API lookup to pwnedpasswords.com.
    Returns the SHA1 hash of the password entered, and the number of times that
    password was found in the database.  0 means it has not been pwned.

    Some code taken from Mike Pound's script that does the same.  Mike's script
    can be found here: <https://github.com/mikepound/pwned-search>
    """
    sha1 = hashlib.sha1(passwd.encode('utf-8')).hexdigest().upper()
    head, tail = sha1[:5], sha1[5:]

    url = API_URL + format(head)
    req = requests.get(url)
    status_code = req.status_code
    if status_code != 200:
        raise RuntimeError('Error fetching "{}": {}'.format(url, status_code))

    hashes = (line.split(':') for line in req.text.splitlines())
    count = next((int(count) for val, count in hashes if val == tail), 0)
    return sha1, count


