#!/usr/bin/env python3
'''Module for Authentication'''
import fnmatch
from flask import request
from typing import List, TypeVar
from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    '''Session Authentication Module'''
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        '''Generates session id for isers'''
        session_id = None if user_id is None or type(
            user_id) != str else str(uuid4())
        if session_id:
            self.user_id_by_session_id[session_id] = user_id
            return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        '''Retreives user_id for session_id'''
        if session_id is None or type(session_id) != str:
            return None
        user_id = self.user_id_by_session_id.get(session_id)
        return user_id
