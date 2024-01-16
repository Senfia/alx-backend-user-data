#!/usr/bin/env python3
""" Module of API authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    ''' A Class to manage the API authentications.
    '''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        ''' Public auth method
        '''
        return False

    def authorization_header(self, request=None) -> str:
        '''Authorization header method
        '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''Current user methode
        '''
        return None
