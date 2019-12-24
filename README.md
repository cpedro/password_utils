# Python Password Utils

Python scripts to perform password related tasks.

This single repository replaced older, separate repositories that are now
deprecated, `pwned_password_search` and `generate_shadow`.

# is_it_pwned.py: Is my password pwned?

Script that checks a password against the
[Have I Been Pwned](https://haveibeenpwned.com/) database, and reports back on
whether or not it has been listed.

You may need to install the `requests` package first before running.
```
$ pip install requests
```
**OR**
```
$ pip3 install requests
```

This method may be preferable to putting your password directly into the site
because this script only sends the first 5 characters of the SHA1 hash of your
password over the internet instead of your whole password or hash.

For more info see the
[API docs](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange)

This script was inspired by Computerphile's
[YouTube video](https://youtu.be/hhUb5iknVJs) featuring
[Mike Pound](https://github.com/mikepound), and later I took some code from the
Python script [he wrote](https://github.com/mikepound/pwned-search) that does
the same thing.

## Running:

```
usage: is_it_pwned.py [-h] [passwords [passwords ...]]

Check if passwords have been comprised.

positional arguments:
  passwords   Password to lookup.

optional arguments:
  -h, --help  show this help message and exit
```

* Prompts you for a single password (echo off):
  ```
  $ python is_it_pwned.py
  ```
* Reads passwords from a file:
  ```
  $ python is_it_pwned.py < file
  ```
* Reads passwords written to standard output by another command:
  ```
  $ cmd | python is_it_pwned.py
  ```
* Checks passwords given command line arguments: (**Beware** the password may
  be saved in shell history and that other users on the system may be able to
  observe the command line.)
  ```
  $ python is_it_pwned.py <password1> [<password2> ...]
  ```

# shadow_hash.py: Generate Shadow Password Hash

Script that can be used to generate a password hash that can be inserted
directly into the `/etc/shadow` file on a Linux or Unix system.

Current supported hash methods (from most secure to least):
* SHA512 (Default)
* SHA256
* MD5

## Running:

```
usage: shadow_hash.py [-h] [-m {SHA512,SHA256,MD5}]
                      [passwords [passwords ...]]

Generate Shadow Hashes.

positional arguments:
  passwords             Password to generate hashes for.

optional arguments:
  -h, --help            show this help message and exit
  -m {SHA512,SHA256,MD5}, --method {SHA512,SHA256,MD5}
                        Hashing method to use, default is SHA512
```

* Prompts you for a single password (echo off):
  ```
  $ python3 shadow_hash.py
  ```
* Reads passwords from a file:
  ```
  $ python3 shadow_hash.py < file
  ```
* Reads passwords written to standard output by another command:
  ```
  $ cmd | python3 shadow_hash.py
  ```
* Checks passwords given command line arguments: (**Beware** the password may
  be saved in shell history and that other users on the system may be able to
  observe the command line.)
  ```
  $ python3 shadow_hash.py <password1> [<password2> ...]
  ```
