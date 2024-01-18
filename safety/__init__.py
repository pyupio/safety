# -*- coding: utf-8 -*-

__author__ = """safetycli.com"""
__email__ = 'support@safetycli.com'

import os

ROOT = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(ROOT, 'VERSION')) as version_file:
    VERSION = version_file.read().strip()
