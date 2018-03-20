# requests-credssp

[![Build Status](https://travis-ci.org/jborean93/requests-credssp.svg?branch=master)](https://travis-ci.org/jborean93/requests-credssp) [![Appveyor Build status](https://ci.appveyor.com/api/projects/status/6osajucq8sf8aeed/branch/master?svg=true)](https://ci.appveyor.com/project/jborean93/requests-credssp/branch/master) [![Coverage Status](https://coveralls.io/repos/github/jborean93/requests-credssp/badge.svg?branch=master)](https://coveralls.io/github/jborean93/requests-credssp?branch=master)


## About this library

This package allows for HTTPS CredSSP authentication using the requests
library. CredSSP is a Microsoft authentication that allows your credentials to
be delegated to a server giving you double hop authentication.


## Features

Supports authenticating with a Windows server using the CredSSP protocol. This
authentication uses either NTLM or Kerberos to initially authenticate a user
before delegating the credentials to the server.


## Installation

requests-credssp supports Python 2.6, 2.7 and 3.4+

Before installing the following packages need to be installed on the system

```bash
# for Debian/Ubuntu/etc:
sudo apt-get install gcc python-dev libssl-dev

# for RHEL/CentOS/etc:
sudo yum install gcc python-devel openssl-devel
```

To install, use pip:

`pip install requests-credssp`

To install from source, download the source code, then run:

`pip install .`


## Requirements

- ntlm-auth
- pyasn1
- six
- pyOpenSSL>=16.0.0
- requests>=2.0.0
- gssapi (Kerberos auth with non Windows hosts)


## Usage

By default CredSSP will attempt to authenticate over a TLS 1.2 connection with
either Kerberos or NTLM auth. Kerberos or NTLM is chosen based on the host
setup with NTLM being a fallback. The following requirements must be met for
Kerberos to be used;

* The kerberos system extensions are installed
* [python-gssapi](https://github.com/pythongssapi/python-gssapi) is installed
* Kerberos is configured to talk to the domain/realm
* The username is in the UPN form `username@REALM.COM`
* The FQDN is used when connecting to the server

You can force requests-credssp to use Kerberos or NTLM by passing in
`auth_mechanism=<type>` in the constructor. See the examples below for more
details.

#### Defaults

Will connect over TLS 1.2 and attempt to authenticate with Kerberos with NTLM
being a fallback if that fails.

```python
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password')
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### With Kerberos Auth

Will connect over TLS 1.2 and only authenticate with Kerberos. NTLM will not be
used as a fallback if that fails.

```python
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('user@DOMAIN.LOCAL', 'password', auth_mechanism='kerberos')
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### With NTLM Auth

This will force NTLM authentication and not attempt to use Kerberos.

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

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', disable_tlsv1_2=True)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
...
```

#### Message Encryption

You can use this library to encrypt and decrypt messages sent to and from the
server. Message encryption is done over the TLS channel that was negotiated in
the authentication stage. The below is an example of encrypting and decrypting
messages, note this is only a basic example and not a working script.

```python
import requests
from requests_credssp import HttpCredSSPAuth

# build the auth request and sent an empty message to authenticate
hostname = "server"
session = requests.Session()
session.auth = HttpCredSSPAuth('domain\\user', 'password')

request = requests.Request('POST', "https://%s:5986/wsman" % server, data=None)
prepared_request = self.session.prepare_request(request)
response = session.send(prepared_request)

context = session.auth.contexts[hostname]
# encrypt the message using the wrap command
message = b'hi server'
encrypted_message = context.wrap(message)

# send the encrypted message and get the encrypted response
request = requests.Request('POST', 'https://server:5986/wsman', data=encrypted_message)
prepared_request = self.session.prepare_request(request)
response = session.send(prepared_request)

# decrypt the encrypted response from the server
encrypted_response = response.content
decrypted_response = context.unwrap(encrypted_response)
```


#### CredSSP Versions

Recently Microsoft has released a security update to CredSSP to mitigate CVE
2018-0886. In this update, the CredSSP protocol versions were updated from
2-4 to 5-6 where version 2 is now 5 while the rest are 6. This change should
be transparent to this library but you can specify a minimum server version to
enforce in your environment. To do this supply the version when creating
HttpCredSSPAuth like so;

```
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', minimum_version=5)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
```

## Logging

This library uses the standard Python logging facilities. Log messages are
logged to the `requests_credssp` and `requests_credssp.credssp` named loggers.

If you are receiving any errors or wish to debug the CredSSP process you should
enable DEBUG level logs. These logs show fine grain information such as the
protocol and cipher negotiated and each CredSSP token used in the
authentication process.


## Backlog

* Replace dependency of pyOpenSSL if possible with inbuilt functions in Python
* Add support for different credential types like smart card and redirected credentials
