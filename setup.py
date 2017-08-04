#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

setup(
    name='requests-credssp',
    version='0.1.0',
    packages=[ 'requests_credssp' ],
    install_requires=[ "ntlm-auth",
                       "ordereddict ; python_version<'2.7'",
                       "pyOpenSSL>=16.0.0",
                       "requests>=2.0.0" ],
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/requests-credssp',
    description='HTTPS CredSSP authentication with the requests library.',
    long_description=long_description,
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
        'Programming Language :: Python :: 3.6'
    ],
)
