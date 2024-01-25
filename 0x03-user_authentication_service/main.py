#!/usr/bin/env python3
"""End-to-end integration test
"""
import requests

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def make_request(method: str, endpoint: str, data=None, cookies=None):
    """Helper function for making HTTP requests."""
    url = f"{BASE_URL}/{endpoint}"
    res = requests.request(method, url, data=data, cookies=cookies)
    return res


def test_register_user(email: str, password: str):
    """Tests registering a new user."""
    endpoint = "users"
    body = {'email': email, 'password': password}
    res = make_request("POST", endpoint, data=body)

    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "user created"}

    # Attempt to register the same user again
    res = make_request("POST", endpoint, data=body)
    assert res.status_code == 400
    assert res.json() == {"message": "email already registered"}


def test_log_in_wrong_password(email: str, password: str):
    """Tests logging in with an invalid password."""
    endpoint = "sessions"
    body = {'email': email, 'password': password}
    res = make_request("POST", endpoint, data=body)

    assert res.status_code == 401


def test_profile_unlogged():
    """Tests retrieving profile information while logged out."""
    endpoint = "profile"
    res = make_request("GET", endpoint)

    assert res.status_code == 403


def test_profile_logged(session_id: str):
    """Tests retrieving profile information while logged in."""
    endpoint = "profile"
    cookies = {'session_id': session_id}
    res = make_request("GET", endpoint, cookies=cookies)

    assert res.status_code == 200
    assert "email" in res.json()


def test_log_out(session_id: str):
    """Tests logging out of a session."""
    endpoint = "sessions"
    cookies = {'session_id': session_id}
    res = make_request("DELETE", endpoint, cookies=cookies)

    assert res.status_code == 200
    assert res.json() == {"message": "Bienvenue"}


def test_reset_password_token(email: str):
    """Tests requesting a password reset."""
    endpoint = "reset_password"
    body = {'email': email}
    res = make_request("POST", endpoint, data=body)

    assert res.status_code == 200
    assert "email" in res.json()
    assert res.json()["email"] == email
    assert "reset_token" in res.json()

    return res.json().get('reset_token')


def test_update_password(email: str, reset_token: str, new_password: str):
    """Tests updating a user's password."""
    endpoint = "reset_password"
    body = {
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password}
    res = make_request("PUT", endpoint, data=body)

    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    test_register_user(EMAIL, PASSWD)
    test_log_in_wrong_password(EMAIL, NEW_PASSWD)
    test_profile_unlogged()
    session_id = test_log_in(EMAIL, PASSWD)
    test_profile_logged(session_id)
    test_log_out(session_id)
    reset_token = test_reset_password_token(EMAIL)
    test_update_password(EMAIL, reset_token, NEW_PASSWD)
    test_log_in(EMAIL, NEW_PASSWD)
