#!/usr/bin/env python3
'''Authentication Module'''
from sqlalchemy.orm.exc import NoResultFound
from bcrypt import checkpw, hashpw, gensalt
from user import User
from uuid import uuid4
from db import DB


def _hash_password(password: str) -> bytes:
    '''Returns salted hash of the input password,'''
    password = password.encode('utf-8')
    hashed_password = hashpw(password, gensalt())
    return hashed_password


def _generate_uuid() -> str:
    '''Return string uuid'''
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        '''Returns user with email and password'''
        try:
            exist = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            user = self._db.add_user(email, hashed_password)
            return user
        raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        '''Locates email and checks password'''
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode('utf-8')
            if (type(user.hashed_password) == str):
                encode_hash = user.hashed_password.encode('utf-8')
            return checkpw(password, encode_hash)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        '''Creates session id'''
        try:
            exist = self._db.find_user_by(email=email)
            exist.session_id = _generate_uuid()
            return exist.session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        '''Returns user from session_id'''
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        '''Updates session_id to None'''
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        '''Creates session id'''
        try:
            exist = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(exist.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        '''Updates user password'''
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
        except NoResultFound:
            raise ValueError
