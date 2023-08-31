#!/usr/bin/env python3
'''Module for encrypting password'''
import bcrypt


def hash_password(password: str) -> bytes:
    '''Function to hash password'''
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''Function to validate password'''
    password = password.encode('utf-8')
    return bcrypt.checkpw(password, hashed_password)
