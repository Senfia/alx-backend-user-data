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
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        # Ensure that paths in excluded_paths are slash-tolerant
        excluded_paths = [p.rstrip('/') for p in excluded_paths]

        # Check if the path is in excluded_paths
        return path.rstrip('/') not in excluded_paths

    def authorization_header(self, request=None) -> str:
        '''Authorization header method
        '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''Current user methode
        '''
        return None
