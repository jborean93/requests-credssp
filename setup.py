#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

from setuptools import setup


def abs_path(rel_path):
    return os.path.join(os.path.dirname(__file__), rel_path)


with open(abs_path('README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')


setup(
    name='requests-credssp',
    version='1.3.1',
    packages=['requests_credssp'],
    install_requires=[
        "cryptography",
        "pyasn1>=0.3.1",
        "pyOpenSSL>=16.0.0",
        "pyspnego",
        "requests>=2.0.0"
    ],
    extras_require={
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'pyspnego[kerberos]',
        ]
    },
    python_requires='>=3.6',
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/requests-credssp',
    description='HTTPS CredSSP authentication with the requests library.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='authentication auth microsoft credssp winrm',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
