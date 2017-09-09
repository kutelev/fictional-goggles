import requests
import pytest
import itertools

from time import sleep
from os import getenv

hostname= getenv('FRICTIONAL_GOGGLES_IP', 'localhost:8081')
restapi_base_url = 'http://{}/restapi'.format(hostname)
known_users = [{'username': 'user{}'.format(i), 'password': '1234'} for i in range(1, 6)]

TRUE_OR_FALSE = 0
FULL_RESPONSE_OR_NONE = 1
TOKEN_OR_NONE = 2


def restapi_url(call):
    return '{}/{}'.format(restapi_base_url, call)


def send_request(call_name, request, ret_type=TRUE_OR_FALSE):
    response = requests.put(restapi_url(call_name), json=request).json()

    if response['status'] == 'ok':
        if ret_type == TRUE_OR_FALSE:
            return True
        elif ret_type == FULL_RESPONSE_OR_NONE:
            return response
        elif ret_type == TOKEN_OR_NONE:
            return response['token']

    assert len(response) == 1
    assert response['status'] == 'failed'

    if ret_type == TRUE_OR_FALSE:
        return False
    else:
        return None


def resetdb():
    return send_request('resetdb', {'magic_key': 'c4f1571a-9450-11e7-a0a6-0b95339866a9'})


def login(username, password):
    return send_request('login', {'username': username, 'password': password}, TOKEN_OR_NONE)


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

    def usermod(self, key=None, new_value=None):
        request = {'token': self.token}

        if key is not None:
            request[key] = new_value

        return send_request('usermod', request, FULL_RESPONSE_OR_NONE)

    @property
    def users(self):
        return send_request('users', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    def add_friend(self, friend_username):
        return send_request('addfriend', {'token': self.token, 'friend_username': friend_username})

    def del_friend(self, friend_username):
        return send_request('delfriend', {'token': self.token, 'friend_username': friend_username})

    @property
    def friends(self):
        return send_request('friends', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    def sendmsg(self, recipient, content):
        return send_request('sendmsg', {'token': self.token, 'recipient': recipient, 'content': content})

    @property
    def messages(self):
        return send_request('messages', {'token': self.token}, FULL_RESPONSE_OR_NONE)


@pytest.fixture(scope="function", autouse=True)
def resetdb_fixture(request):
    def teardown():
        resetdb()
    request.addfinalizer(teardown)


def setup_module():
    resetdb()


def test_login_logout():
    for user in known_users:
        token = login(user['username'], user['password'])
        assert token
        assert logout(token)


def test_login_non_existing_user():
    assert login('non', 'existing') is None


def test_login_multiple_logins():
    user = known_users[0]
    tokens = set()
    for _ in range(10):
        tokens.add(login(user['username'], user['password']))
    assert len(tokens) == 10
    for token in tokens:
        assert logout(token)


def test_login_session_count_limit():
    user = known_users[0]
    tokens1 = set()
    tokens2 = set()
    for _ in range(128):
        tokens1.add(login(user['username'], user['password']))
    assert len(tokens1) == 128
    for _ in range(128):
        tokens2.add(login(user['username'], user['password']))
    for token in tokens1:
        assert not logout(token)
    for token in tokens2:
        assert logout(token)


def test_login_last_login():
    user = known_users[0]
    dates = set()
    for _ in range(10):
        sleep(0.01)
        with Session(user['username'], user['password']) as session:
            remote_user = session.usermod()
            assert remote_user is not None
            assert 'last_login' in remote_user
            dates.add(remote_user['last_login'])
    assert len(dates) == 10


def test_usermod_change_user_name_forbiddance():
    user = known_users[0]
    with Session(user['username'], user['password']) as session:
        assert session.usermod('username', 'new_user_name') is None


def test_usermod_change_password():
    user = known_users[0]
    old_password = user['password']
    new_password = old_password[::-1]
    with Session(user['username'], old_password) as session:
        assert session.usermod('password', new_password) is not None
    assert login(user['username'], old_password) is None
    with Session(user['username'], new_password) as session:
        assert session.token
        assert session.usermod('password', old_password) is not None
    with Session(user['username'], old_password) as session:
        assert session.token


def test_add_del_friend():
    for user1, user2 in itertools.product(known_users, known_users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not session.add_friend(user2['username'])
            else:
                assert session.add_friend(user2['username'])
                assert not session.add_friend(user2['username'])

    for user1, user2 in itertools.product(known_users, known_users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not session.del_friend(user2['username'])
            else:
                assert session.del_friend(user2['username'])
                assert not session.del_friend(user2['username'])


def test_sendmsg():
    for user1, user2 in itertools.product(known_users, known_users):
        packed_user1 = user1['username'], user1['password']
        packed_user2 = user2['username'], user2['password']
        with Session(*packed_user1) as session1, Session(*packed_user2) as session2:
            if user1['username'] == user2['username']:
                assert not session1.add_friend(user2['username'])
                assert not session1.sendmsg(user2['username'], 'message')
            else:
                assert not session1.sendmsg(user2['username'], 'message')
                assert not session2.sendmsg(user1['username'], 'message')
                assert session1.add_friend(user2['username'])
                assert not session1.sendmsg(user2['username'], 'message')
                assert not session2.sendmsg(user1['username'], 'message')
                assert session2.add_friend(user1['username'])
                assert session1.sendmsg(user2['username'], 'message')
                assert session2.sendmsg(user1['username'], 'message')
                assert session1.del_friend(user2['username'])
                assert session2.del_friend(user1['username'])
    for user in known_users:
        with Session(user['username'], user['password']) as session:
            messages = session.messages
            assert messages is not None
            assert messages['status'] == 'ok'
            messages = messages['messages']
            assert len(messages) == 2 * (len(known_users) - 1)
            for message in messages:
                assert message['content'] == 'message'


def test_users():
    cur_user = known_users[0]
    semi_friend = known_users[1]
    complete_friend = known_users[2]
    real_usernames = set()
    with Session(cur_user['username'], cur_user['password']) as session:
        assert session.add_friend(semi_friend['username'])
        assert session.add_friend(complete_friend['username'])
    with Session(complete_friend['username'], complete_friend['password']) as session:
        assert session.add_friend(cur_user['username'])
    with Session(cur_user['username'], cur_user['password']) as session:
        real_users = session.users
        assert real_users is not None
        assert real_users['status'] == 'ok'
        real_users = real_users['users']
        for user in real_users:
            if user['username'] == semi_friend['username']:
                assert user['is_friend'] == 1
            if user['username'] == complete_friend['username']:
                assert user['is_friend'] == 2
            real_usernames.add(user['username'])
    assert real_usernames == set([user['username'] for user in known_users])


def test_friends():
    cur_user = known_users[0]
    semi_friend = known_users[1]
    complete_friend = known_users[2]

    with Session(cur_user['username'], cur_user['password']) as session:
        friends = session.friends
        assert friends is not None
        assert friends['status'] == 'ok'
        assert len(friends['friends']) == 0
        assert session.add_friend(semi_friend['username'])
        assert session.add_friend(complete_friend['username'])
    with Session(complete_friend['username'], complete_friend['password']) as session:
        assert session.add_friend(cur_user['username'])
    with Session(cur_user['username'], cur_user['password']) as session:
        friends = session.friends
        assert friends is not None
        assert friends['status'] == 'ok'
        assert len(friends['friends']) == 2
        friends = friends['friends']
        for friend in friends:
            if friend['username'] == semi_friend['username']:
                assert friend['is_friend'] == 1
            if friend['username'] == complete_friend['username']:
                assert friend['is_friend'] == 2
