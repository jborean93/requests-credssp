# requests-credssp

[![Build Status](https://travis-ci.org/jborean93/requests-credssp.svg?branch=master)](https://travis-ci.org/jborean93/requests-credssp) [![Appveyor Build status](https://ci.appveyor.com/api/projects/status/6osajucq8sf8aeed/branch/master?svg=true)](https://ci.appveyor.com/project/jborean93/requests-credssp/branch/master) [![Coverage Status](https://coveralls.io/repos/github/jborean93/requests-credssp/badge.svg?branch=master)](https://coveralls.io/github/jborean93/requests-credssp?branch=master)


## About this library

This package allows for HTTPS CredSSP authentication using the requests
library. CredSSP is a Microsoft authentication that allows your credentials to
be delegated to a server giving you double hop authentication.


## Features

Currently only CredSSP is supported through NTLM with later plans on adding
support for Kerberos. CredSSP allows you to connect and delegate your
credentials to a computer that has CredSSP enabled.


## Installation

requests-credssp supports Python 2.6, 2.7 and 3.3+

Before installing the following packages need to be installed on the system

```bash
# for Debian/Ubuntu/etc:
sudo apt-get install gcc python-dev libssl-dev

# for RHEL/CentOS/etc:
sudo yum install gcc python-devel openssl-devel
```

To install, use pip:

```bash
pip install requests-credssp
```

To install from source, download the source code, then run:

```bash
python setup.py install
```


## Requirements

- ntlm-auth
- ordereddict (Python 2.6 Only)
- pyOpenSSL>=16.0.0
- requests>=2.0.0


## Usage

#### With NTLM Auth

Currently this is the only way to use CredSSP, there are plans in the future to
add Kerberos auth support as well.

```python
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', auth_mechanism='ntlm')
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### Disable TLSv1.2

There is an option to disable TLSv1.2 connections and revert back to TLSv1.
Windows 7 and Server 2008 did not support TLSv1.2 by default and require a
patch be installed and registry keys modified to allow TLSv1.2 support.

```python
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', auth_mechanism='ntlm', disable_tlsv1_2=True)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### Message Encryption

You can use this library to encrypt and decrypt messages sent ot and from the
server. Message encryption is done over the TLS channel that was negotiated in
the authentication stage. The below is an example of encrypting and decrypting
messages, note this is only a basic example and not a working script.

```python
import requests
from requests_credssp import HttpCredSSPAuth

# build the auth request and sent an empty message to authenticate
session = requests.Session()
session.auth = HttpCredSSPAuth('domain\\user', 'password')

request = requests.Request('POST', 'https://server:5986/wsman', data=None)
prepared_request = self.session.prepare_request(request)
response = session.send(prepared_request)

# encrypt the message using the wrap command
message = b'hi server'
encrypted_message = session.auth.wrap(message)

# send the encrypted message and get the encrypted response
request = requests.Request('POST', 'https://server:5986/wsman', data=encrypted_message)
prepared_request = self.session.prepare_request(request)
response = session.send(prepared_request)

# decrypt the encrypted response from the server
encrypted_response = response.content
decrypted_response = session.auth.unwrap(encrypted_response)
```


## Backlog

* Add support for Kerberos authentication
* Once above is added, auto detect which version to use, preference Kerberos over NTLM
* Replace dependency of pyOpenSSL if possible with inbuilt functions in Python
* Add support for different credential types like smart card and redirected credentials
