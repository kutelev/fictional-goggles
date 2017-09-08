import requests
import pytest


restapi_base_url = 'http://localhost:8081/restapi'
users = [{'username': 'user{}'.format(i), 'password': '1234'} for i in range(1, 6)]


def restapi_url(call):
    return '{}/{}'.format(restapi_base_url, call)


def login(username, password):
    response = requests.put(restapi_url('login'),
                            json={'username': username, 'password': password})

    response = response.json()

    if response['status'] == 'ok':
        return response['token']

    return None


class Session():
    def __init__(self, username, password):
        self.token = login(username, password)
        assert self.token

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        assert logout(self.token)


def logout(token):
    response = requests.put(restapi_url('logout'),
                            json={'token': token})

    response = response.json()

    if response['status'] == 'ok':
        return True

    return False


def change_password(token, new_password):
    response = requests.put(restapi_url('usermod'),
                            json={'token': token, 'password': new_password})

    response = response.json()

    if response['status'] == 'ok':
        return True

    return False


def test_login_logout():
    for user in users:
        token = login(user['username'], user['password'])
        assert token
        assert logout(token)


def test_login_non_existing_user():
    assert login('non', 'existing') is None


def test_login_multiple_logins():
    user = users[0]
    tokens = set()
    for _ in range(10):
        tokens.add(login(user['username'], user['password']))
    assert len(tokens) == 10
    for token in tokens:
        assert logout(token)


def test_usermod_change_password():
    user = users[0]
    old_password = user['password']
    new_password = old_password[::-1]
    with Session(user['username'], old_password) as session:
        assert change_password(session.token, new_password)
    assert login(user['username'], old_password) is None
    with Session(user['username'], new_password) as session:
        assert session.token
        assert change_password(session.token, old_password)
    with Session(user['username'], old_password) as session:
        assert session.token

