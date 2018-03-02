# Changes

## 0.2.0 (TBD)

* Added support for Kerberos authentication over CredSSP
* Tidied up test suite to use py.test and added pep8 checks
* Drop support for Python 3.3

## 0.1.0 (Jul 7, 2017)

* Added support for using the TLS context to encrypt payload data
* Tidied up the dependencies to set a minimum required version for pyOpenSSL and requests
* Set ordereddict to only be a dependency for Python 2.6

## 0.0.2 (Mar 17, 2017)

* Small fix for older version of pyOpenSSL don't fail when this library is loaded


## 0.0.1 (Aug 29, 2016)

Initial Commit, supports

* Full support for CredSSP using NTLM authentication
* TLSv1.2 by default, ability to use TLSv1 if flag is used
