requests-credssp
================

About this library
------------------

This package allows for HTTPS CredSSP authentication using the requests library. CredSSP is a Microsoft authentication that allows your credentials to be delegated to a server giving you double hop authentication.


Features
--------

Currently only CredSSP is supported through NTLM with later plans on adding support for Kerberos. This will allow you to connect and delegate your credentials to a domain joined computer that has CredSSP enabled.


Installation
------------

requests-credssp supports Python 2.6, 2.7 and 3.3+

To install, use pip:

    pip install requests-credssp

To install from source, download the source code, then run:

    python setup.py install


Requirements
------------

- ntlm-auth
- ordereddict (Python 2.6 Only)
- pyOpenSSL
- requests


Usage
------------

#### With NTLM Auth

Currently this is the only way to use CredSSP, there are plans in the future to add Kerberos auth support as well.

```python
import requests
from requests_credssp import CredSSPAuth

credssp_auth = CredSSPAuth('domain\\user', 'password', auth_mechanism='ntlm')
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### Disable TLSv1.2

There is an option to disable TLSv1.2 connections and revert back to TLSv1. Windows 7 and Server 2008 did not support TLSv1.2 by default and require a patch be installed and registry keys modified to allow TLSv1.2 support.

```python
import requests
from requests_credssp import CredSSPAuth

credssp_auth = CredSSPAuth('domain\\user', 'password', auth_mechanism='ntlm', disable_tlsv1_2=True)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

Backlog
-------
* Add support for Kerberos authentication
* Once above is added, auto detect which version to use, preference Kerberos over NTLM
* Generic functions for other protocols to call to encrypt messages before sending over the wire
* Replace dependency of pyOpenSSL if possible with inbuilt functions in Python
* Create tests to test out the code
* Fix up asn_structures and asn_helper to be more readable
* Add support for different credential types like smart card and redirected credentials