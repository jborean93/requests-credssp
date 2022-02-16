# Changelog

## 1.3.1 - 2022-02-16

* Fix usage of recently removed pyspnego feature


## 1.3.0 - 2021-10-22

* Dropped Python 2.7 and 3.5, new minimum is 3.6
* Added Linux kerberos dependency of [pykrb5](https://github.com/jborean93/pykrb5) to line up with `pyspnego` deps


## 1.2.0 - 2020-08-14

* Changed authentication library from `ntlm-auth`, `gssapi`, or `pywin32` to `pyspnego`.
* Dropped support for Python 2.6 and Python 3.4


## 1.1.1 - 2019-12-20

* Fixed `StopIterator` error when `gssapi`, `gss-ntlmssp` is installed and NTLM auth was negotiated with SPNEGO.


## 1.1.0 - 2019-08-19

* Bumped `ntlm-auth` minimum version to `v1.2.0`
* Use new NTLM context object to avoid having to base64 encode/decode the messages
* Fix invalid regex escape sequences that have been deprecated in Python 3.8
* Include `LICENSE` and `CHANGES.md` in the Python package manifest


## 1.0.2 - 2018-11-14

* Changed some log messages to a debug level instead of info


## 1.0.1 - 2018-09-25

* Added support for Python 3.7
* Fix version info warning msg for pub key authentication process


## 1.0.0 - 2018-04-10

* Drop support for Python 3.3
* Added support for new CredSSP protocol 5 and 6, mitigates CVE 2018-0886
* Added the ability to specify a minimum CredSSP server version
* Added support for SPNEGO/Kerberos authentication over CredSSP
* Removed manual asn.1 structures and added dependency on pyasn1 for easier
  code management
* Deprecated older function in HttpCredSSPAuth that should be host specific
  instead of global
* Changed license to MIT from ISC
* Tidied up test suite to use py.test and added pep8 checks


## 0.1.0 - 2017-07-07

* Added support for using the TLS context to encrypt payload data
* Tidied up the dependencies to set a minimum required version for pyOpenSSL and requests
* Set ordereddict to only be a dependency for Python 2.6


## 0.0.2 - 2017-03-17

* Small fix for older version of pyOpenSSL don't fail when this library is loaded


## 0.0.1 - 2016-08-29

Initial Commit, supports

* Full support for CredSSP using NTLM authentication
* TLSv1.2 by default, ability to use TLSv1 if flag is used
