# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

from logging import NullHandler

from requests_credssp.credssp import HttpCredSSPAuth


logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())

__all__ = 'HttpCredSSPAuth'
