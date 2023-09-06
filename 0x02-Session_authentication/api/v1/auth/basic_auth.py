#!/usr/bin/env python3
'''Module for Basic Auth'''
from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    '''Basic Authentication Class'''

    def extract_base64_authorization_header(self, authorization_header: str) -> str:  # nopep8
        '''Returns Base64 part of Authorization header'''
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split()[1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:  # nopep8
        '''Returns decoded value of base64 string'''
        if base64_authorization_header is None or not isinstance(base64_authorization_header, str):  # nopep8
            return None
        try:
            test = b64decode(base64_authorization_header)
        except Exception:
            return None
        return test.decode('utf-8')

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):  # nopep8
        '''Returns the user email and password from the decoded value.'''
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):  # nopep8
        '''Returns User instance based on his email and password.'''
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User().search({"email": user_email})
        except Exception:
            return None
        if len(users) < 1:
            return None
        if not users[0].is_valid_password(user_pwd):
            return None
        return users[0]

    def current_user(self, request=None) -> TypeVar('User'):
        '''Retrieves the User instance for a request'''
        header = Auth().authorization_header(request)
        b64_header = self.extract_base64_authorization_header(header)
        decoded_header = self.decode_base64_authorization_header(b64_header)
        email, password = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(email, password)
