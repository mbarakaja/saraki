# -*- coding: utf-8 -*-

"""Top-level package for Saraki."""

__author__ = """José María Domínguez Moreno"""
__email__ = "miso.0b11@gmail.com"
__version__ = "0.1.0a0"


from saraki.app import Saraki, Blueprint  # noqa: F401
from saraki.auth import require_auth  # noqa: F401
