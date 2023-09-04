#!/usr/bin/env python3
'''Module for Authentication'''
from flask import request
from typing import List, TypeVar


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''Function to seed paths'''
        if path is not None and excluded_paths is not None and len(excluded_paths) > 0:  # nopep8
            if path.endswith('/'):
                path = path[:-1]
            for excluded_path in excluded_paths:
                if excluded_path.endswith('/'):
                    excluded_path = excluded_path[:-1]
                if excluded_path == path:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        '''Function that handles authorization'''
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''Checks for current user'''
        return None
