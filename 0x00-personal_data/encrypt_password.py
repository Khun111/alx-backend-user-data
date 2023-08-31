'''Module for encrypting password'''
import bcrypt
from typing import ByteString


def hash_password(password: str) -> ByteString:
    '''Function to hash password'''
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


def is_valid(hashed_password: ByteString, password: str) -> bool:
    '''Function to validate password'''
    password = password.encode('utf-8')
    return bcrypt.checkpw(password, hashed_password)
