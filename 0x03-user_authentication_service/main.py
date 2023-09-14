#!/usr/bin/env python3
"""
Main file
"""

import requests

base_url = 'http//:localhost:5000/'


def register_user(email: str, password: str) -> None:
    '''Test register_user endpoint'''
    response = requests.post(
        f'{base_url}users', data={'email': email, 'password': password})
    if response.status_code == 200:
        assert (
            response.json() == {"email": email, "message": "user created"})
    if response.status_code == 400:
        assert (
            response.json() == {"message": "email already registered"})


def log_in_wrong_password(email: str, password: str) -> None:
    '''Test login with wrong password'''
    response = requests.post(f'{base_url}sessions', data={
                             'email': email, 'password': password})
    assert (response.status_code == 401)


def log_in(email: str, password: str) -> str:
    '''Test login endpoint'''
    response = requests.post(f'{base_url}sessions', data={
                             'email': email, 'password': password})
    assert (response.status_code == 200)
    assert (response.json() == {"email": email, "message": "logged in"})
    return response.cookies.get('sesssion_id')


def profile_unlogged() -> None:
    '''Test if user\'s unlogged in session'''
    response = requests.get(f'{base_url}profile')
    assert (response.status_code == 403)


def profile_logged(session_id: str) -> None:
    '''Test if user\'s logged in session'''
    response = requests.get(f'{base_url}profile', data={
                            'sesssion_id': sesssion_id})
    assert (response.status_code == 200)


def log_out(session_id: str) -> None:
    '''Test logout endpoint'''
    response = requests.delete(f'{base_url}sessions', cookies={
                               'session_id': session_id})
    assert (response.url == base_url)


def reset_password_token(email: str) -> str:
    '''Reset password endpoint'''

    response = requests.post(
        f'{base_url}reset_password', data={'email': email})
    if response.status_code == 200:
        return response.json()['reset_token']
    else:
        assert (response.status_code == 403)


def update_password(email: str, reset_token: str, new_password: str) -> None:
    '''Update password endpoint'''
    response = requests.post(f'{base_url}reset_password', data={
                                'email': email, 'new_password': new_password,
                                'reset_token': reset_token})
    if response.status_code == 200:
        assert (
            response.json() == {"email": email,
                                "message": "Password updated"})
    else:
        assert (response.status_code == 403)


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    '''Run main file'''

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
