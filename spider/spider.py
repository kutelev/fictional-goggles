import requests
import pytest
import itertools

from time import sleep

restapi_base_url = 'http://localhost:8081/restapi'
users = [{'username': 'user{}'.format(i), 'password': '1234'} for i in range(1, 6)]


def restapi_url(call):
    return '{}/{}'.format(restapi_base_url, call)


def send_request(call_name, request):
    response = requests.put(restapi_url(call_name), json=request).json()

    if response['status'] == 'ok':
        return True

    assert len(response) == 1
    assert response['status'] == 'failed'

    return False


def resetdb():
    return send_request('resetdb', {'magic_key': 'c4f1571a-9450-11e7-a0a6-0b95339866a9'})


def login(username, password):
    response = requests.put(restapi_url('login'),
                            json={'username': username, 'password': password})

    response = response.json()

    if response['status'] == 'ok':
        return response['token']

    assert len(response) == 1
    assert response['status'] == 'failed'

    return None


def logout(token):
    return send_request('logout', {'token': token})


class Session:
    def __init__(self, username, password):
        self.token = login(username, password)
        assert self.token

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        assert logout(self.token)


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


def add_friend(token, friend_username):
    return send_request('addfriend', {'token': token, 'friend_username': friend_username})


def del_friend(token, friend_username):
    return send_request('delfriend', {'token': token, 'friend_username': friend_username})


def sendmsg(token, recipient, content):
    return send_request('sendmsg', {'token': token, 'recipient': recipient, 'content': content})


@pytest.fixture(scope="function", autouse=True)
def resetdb_fixture(request):
    def teardown():
        resetdb()
    request.addfinalizer(teardown)


def setup_module():
    resetdb()


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
    for user1, user2 in itertools.product(users, users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not add_friend(session.token, user2['username'])
            else:
                assert add_friend(session.token, user2['username'])
                assert not add_friend(session.token, user2['username'])

    for user1, user2 in itertools.product(users, users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not del_friend(session.token, user2['username'])
            else:
                assert del_friend(session.token, user2['username'])
                assert not del_friend(session.token, user2['username'])


def test_sendmsg():
    for user1, user2 in itertools.product(users, users):
        packed_user1 = user1['username'], user1['password']
        packed_user2 = user2['username'], user2['password']
        with Session(*packed_user1) as session1, Session(*packed_user2) as session2:
            if user1['username'] == user2['username']:
                assert not add_friend(session1.token, user2['username'])
                assert not sendmsg(session1.token, user2['username'], 'message')
            else:
                assert not sendmsg(session1.token, user2['username'], 'message')
                assert not sendmsg(session2.token, user1['username'], 'message')
                assert add_friend(session1.token, user2['username'])
                assert not sendmsg(session1.token, user2['username'], 'message')
                assert not sendmsg(session2.token, user1['username'], 'message')
                assert add_friend(session2.token, user1['username'])
                assert sendmsg(session1.token, user2['username'], 'message')
                assert sendmsg(session2.token, user1['username'], 'message')
                assert del_friend(session1.token, user2['username'])
                assert del_friend(session2.token, user1['username'])
