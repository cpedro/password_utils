# -*- coding: utf-8 -*-
"""
File: shadow.py
Description: Tasks related to password shadow files.

Current supported hash methods (from most secure to least):
    * SHA512 (Default)
    * SHA256
    * MD5

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

import crypt

"""Dictionary of supported hash methods.
"""
HASH_METHODS = {
    'SHA512': crypt.METHOD_SHA512,
    'SHA256': crypt.METHOD_SHA256,
    'MD5': crypt.METHOD_MD5,
}


def generate_hash(passwd, method):
    """Hash a password and return the hash.
    """
    passwd = passwd.strip()

    try:
        return crypt.crypt(passwd, crypt.mksalt(HASH_METHODS[method.upper()]))
    except KeyError:
        raise ValueError('Hash method {} not supported.'.format(method))
    except Exception as exception:
        raise exception


