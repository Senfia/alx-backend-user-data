#!/usr/bin/env python3
""" Module of API authentication
"""
from flask import request
from typing import List, TypeVar


class BasicAuth:
    ''' A Class to manage the API authentications.
    '''