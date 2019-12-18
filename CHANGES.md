# Changes

## 1.1.1 (TBD)

* Fixed `StopIterator` error when `gssapi`, `gss-ntlmssp` is installed and NTLM auth was negotiated with SPNEGO.


## 1.1.0 (Aug 19, 2019)

* Bumped `ntlm-auth` minimum version to `v1.2.0`
* Use new NTLM context object to avoid having to base64 encode/decode the messages
* Fix invalid regex escape sequences that have been deprecated in Python 3.8
* Include `LICENSE` and `CHANGES.md` in the Python package manifest


## 1.0.2 (Nov 14, 2018)

* Changed some log messages to a debug level instead of info


## 1.0.1 (Sep 25, 2018)

* Added support for Python 3.7
* Fix version info warning msg for pub key authentication process


## 1.0.0 (Apr 10, 2018)

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
