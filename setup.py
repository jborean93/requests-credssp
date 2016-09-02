#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='requests-credssp',
    version='0.0.1',
    packages=[ 'requests_credssp' ],
    install_requires=[ 'ntlm-auth',
                       'ordereddict',
                       'pyOpenSSL',
                       'requests' ],
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/requests-credssp',
    description='HTTPS CredSSP authentication with the requests library.',
    keywords='authentication auth microsoft credssp winrm',
    license='ISC',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
