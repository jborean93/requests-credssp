# requests-credssp

[![Test workflow](https://github.com/jborean93/requests-credssp/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/requests-credssp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/requests-credssp/branch/master/graph/badge.svg)](https://codecov.io/gh/jborean93/requests-credssp)
[![PyPI version](https://badge.fury.io/py/requests-credssp.svg)](https://badge.fury.io/py/requests-credssp)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/request-credssp/blob/master/LICENSE)


## About this library

This package allows for HTTPS CredSSP authentication using the requests
library. CredSSP is a Microsoft authentication that allows your credentials to
be delegated to a server giving you double hop authentication.


## Features

This library supports the following CredSSP features

* Protocol version 2 to 6
* Initial authentication with NTLM or Kerberos
* Message encryption support using the `wrap` and `unwrap` functions


## Requirements

The following Python libraries are required;

* Python 3.6+
* [cryptography](https://github.com/pyca/cryptography)
* [pyasn1>=0.3.1](https://github.com/etingof/pyasn1)
* [pyOpenSSL>=16.0.0](https://github.com/pyca/pyopenssl)
* [pyspnego](https://github.com/jborean93/pyspnego)
* [requests>=2.0.0](https://pypi.python.org/pypi/requests)
* For Kerberos authentication on Unix [python-gssapi>=1.5.0](https://github.com/pythongssapi/python-gssapi) and [pykrb5](https://github.com/jborean93/pykrb5)

By default, this library can authenticate with a Windows host using NTLM
messages, if Kerberos authentication is desired, please read the below.


## Installation

To install requests-credssp, simply run

```
pip install requests-credssp

# to install the optional Kerberos functionality, run (see below)
pip install requests-credssp[kerberos]
```


### Kerberos on Linux

To add support for Kerberos authentication on a non-Windows host, the Kerberos
system headers must be installed and the `python-gssapi` library installed. To
install the Kerberos system headers you can install the following packages;

```
# Via Yum (Centos RHEL)
yum -y install python-devel krb5-devel krb5-libs krb5-workstation

# Via Dnf (Fedora)
dnf -y install python-devel krb5-devel krb5-libs krb5-workstation

# Via Apt (Ubuntu)
apt-get -y install python-dev libkrb5-dev krb5-user

# Via Portage (Gentoo)
emerge -av app-crypt/mit-krb5
emerge -av dev-python/setuptools

# Via pkg (FreeBSD)
sudo pkg install security/krb5

# Via OpenCSW (Solaris)
pkgadd -d http://get.opencsw.org/now
/opt/csw/bin/pkgutil -U
/opt/csw/bin/pkgutil -y -i libkrb5_3

# Via Pacman (Arch Linux)
pacman -S krb5
```

Once installed, the Python Kerberos libraries can be installed with

```
pip install requests-credssp[kerberos]
```

Once installed, the file `/etc/krb5.conf` should be configured so it can talk
with the Kerberos KDC.

To add proper SPNEGO support with `python-gssapi`, the
[gss-ntlmssp](https://github.com/simo5/gss-ntlmssp) should also be installed
which adds NTLM as a supported GSSAPI mechanism required for proper SPNEGO
interoperability with Windows. This package can be installed with;

```
# Via Yum (Centos RHEL) - requires epel-release
yum -y install epel-release
yum -y install gssntlmssp

# Via Dnf (Fedora)
dnf -y install gssntlmssp

# Via Apt (Ubuntu)
apt-get -y install gss-ntlmssp

# Via Pacman (Arch Linux)
pacman -S gss-ntlmssp
```

## Additional Info

The CredSSP protocol is quite complex and uses a lot of other protocols or
standards to work properly. This unfortunately means some older hosts or
settings are incompatible or require some workarounds to get working. Currently
you can configure the following settings when initialising the CredSSP class;

* `auth_mechanism`: The authentication mechanism to use initially, default is `auto`
* `disable_tlsv1_2`: Whether to disable `TLSv1.2` support and work with older protocols like `TLSv1.0`, default is `False`
* `minimum_version`: The minimum CredSSP server version that is required by the client, default is `2`

### Authentication Mechanisms

Part of the CredSSP protocol is to authenticate the user's credentials using
the SPNEGO protocol. The SPNEGO protocol is also called `Negotiate` and is
able to negotiate a common protocol between the client and the server which
can currently be either `NTLM` or `Kerberos`. Kerberos is a tricky protocol
to have set up but should be used wherever it is possible as NTLM uses older
standards that are considered broken from a security perspective.

Due to historical decisions and that Kerberos is not always available by
default, the base install of `requests-credssp` will only work with `NTLM`.
When the Kerberos packages are installed and configured, `requests-credssp`
will automatically attempt to use `Kerberos` if possible but fall back to
`NTLM` if it fails like it would with `SPNEGO`. If you wish to force either
`Kerberos` or `NTLM` instead of relying on the `SPNEGO` mechanism, you can set
`auth_mechanism=<auth_mech>` when creating `HttpCredSSPAuth` like so;

```
import requests
from requests_credssp import HttpCredSSPAuth

# use SPNEGO (default if omitted)
credssp_auth = HttpCredSSPAuth('domain\\user', 'password',
                               auth_mechanism='auto')

# only allow Kerberos
credssp_auth = HttpCredSSPAuth('user@REALM.COM', 'password',
                               auth_mechanism='kerberos')


# only allow NTLM
credssp_auth = HttpCredSSPAuth('domain\\user', 'password',
                               auth_mechanism='ntlm')


r = requests.get("https://server:5986/wsman", auth=credssp_auth)
```

### TLS Protocol Versions

As CredSSP uses TLS to encrypt the tokens that are transferred between the
client and the server, it is succeptible to differing implementations of SSL.
By default, `requests-credssp` will work with server's that offer TLSv1.2
but older Windows hosts that do not support this newer protocol version will

TLSv1.2 was added in Windows Server 2012 and Windows 8 where older hosts need
an optional update to be installed for it to work. If this update cannot be
installed or you are willing to accept the risks of using the older TLS
protocols, `requests-credssp` can be set to disable TLSv1.2 and work with
older protocols like so;


```python
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', disable_tlsv1_2=True)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
```

### CredSSP Protocol Versions

Recently Microsoft has released a security update to CredSSP to mitigate
[CVE 2018-0886](https://support.microsoft.com/en-us/help/4093492/credssp-updates-for-cve-2018-0886-march-13-2018).
The update added 2 new CredSSP protocol versions, `5` and `6` which changes
the way the client and server authenticate each other. While these changes are
transparent to someone who uses this library, it may be prudent to set the
minimum version that this client would authenticate with. This means that any
older server's who have not been patched for this vulnerability will be
rejected.

To set a minimum protocol version that will only allow servers that have been
patched for `CVE 2018-0886`, set `minimum_version=5` when creating
`HttpCredSSPAuth` like so;

```
import requests
from requests_credssp import HttpCredSSPAuth

credssp_auth = HttpCredSSPAuth('domain\\user', 'password', minimum_version=5)
r = requests.get("https://server:5986/wsman", auth=credssp_auth)
```

### Message Encryption

You can use this library to encrypt and decrypt messages sent to and from the
server. Message encryption is done over the TLS channel that was negotiated in
the authentication stage. The below is an example of encrypting and decrypting
messages, note this is only a basic example and not a working script and the
actual implementation depends on the protocol that is reading the messages.

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
