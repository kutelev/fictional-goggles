import requests
import pytest

from time import sleep

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

    assert len(response) == 1
    assert response['status'] == 'failed'

    return None


class Session:
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

    assert len(response) == 1
    assert response['status'] == 'failed'

    return False


def usermod(token, key=None, new_value=None):
    request = {'token': token}

    if key is not None:
        request[key] = new_value

    response = requests.put(restapi_url('usermod'), json=request).json()

    if response['status'] == 'ok':
        return response

    assert len(response) == 1
    assert response['status'] == 'failed'

    return None


def add_or_del_friend(token, friend_username, add=True):
    response = requests.put(restapi_url('addfriend' if add else 'delfriend'),
                            json={'token': token, 'friend_username': friend_username})

    response = response.json()

    if response['status'] == 'ok':
        return True

    assert len(response) == 1
    assert response['status'] == 'failed'

    return False


def add_friend(token, friend_username):
    return add_or_del_friend(token, friend_username, True)


def del_friend(token, friend_username):
    return add_or_del_friend(token, friend_username, False)


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


def test_login_last_login():
    user = users[0]
    dates = set()
    for _ in range(10):
        sleep(0.01)
        with Session(user['username'], user['password']) as session:
            remote_user = usermod(session.token)
            assert remote_user is not None
            assert 'last_login' in remote_user
            dates.add(remote_user['last_login'])
    assert len(dates) == 10


def test_usermod_change_user_name_forbiddance():
    user = users[0]
    with Session(user['username'], user['password']) as session:
        assert usermod(session.token, 'username', 'new_user_name') is None


def test_usermod_change_password():
    user = users[0]
    old_password = user['password']
    new_password = old_password[::-1]
    with Session(user['username'], old_password) as session:
        assert usermod(session.token, 'password', new_password) is not None
    assert login(user['username'], old_password) is None
    with Session(user['username'], new_password) as session:
        assert session.token
        assert usermod(session.token, 'password', old_password) is not None
    with Session(user['username'], old_password) as session:
        assert session.token


def test_add_del_friend():
    user1 = users[0]
    user2 = users[1]
    with Session(user1['username'], user1['password']) as session:
        assert add_friend(session.token, user2['username'])
        assert not add_friend(session.token, user2['username'])
        assert del_friend(session.token, user2['username'])
        assert not del_friend(session.token, user2['username'])