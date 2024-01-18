#!/usr/bin/env python3
""" Module of API authentication
"""
from flask import request
from typing import List, TypeVar
import fnmatch


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

        for excluded_path in excluded_paths:
            if fnmatch.fnmatch(path, excluded_path.rstrip('*')):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        '''Authorization header method
        '''
        if request is None or 'Authorization' not in request.headers:
            return None

        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        '''Current user methode
        '''
        request = Flask(__name__)
        return None
