import requests
import pytest
import itertools
import argparse
import sys

from time import sleep
from os import getenv
from random import choice
from multiprocessing import Pool

hostname = getenv('FRICTIONAL_GOGGLES_IP', 'localhost:8081')
restapi_base_url = 'http://{}/restapi'.format(hostname)

first_names = ['Vasiliy', 'Anatoly', 'Alexandr', 'Alexey', 'Pert', 'Vladimir', 'Ilya', 'Innokentiy']
last_names = ['Ivanov', 'Sidorov', 'Petrov', 'Maksimov', 'Kozlov', 'Popov']
hobbies = ['Screaming', 'Yelling', 'Dancing', 'Drilling', 'Singing', 'Swimming', 'Flying']


def generate_user(i):
    return {'username': 'user{}'.format(i),
            'password': '1234',
            'email': 'user{}@users.com'.format(i),
            'real_name': '{} {}'.format(choice(first_names), choice(last_names)),
            'hobby': choice(hobbies)}


initial_users = [generate_user(i) for i in range(1, 6)]

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


def register(user):
    return send_request('register', user)


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

    def mark_as_read(self, message):
        request = {'token': self.token, 'message_id': message['_id'], 'action': 'mark_as_read'}
        return send_request('msgmod', request)

    def mark_as_unread(self, message):
        request = {'token': self.token, 'message_id': message['_id'], 'action': 'mark_as_unread'}
        return send_request('msgmod', request)

    @property
    def messages(self):
        return send_request('messages', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    @property
    def all_messages(self):
        return send_request('messages', {'token': self.token, 'include_read': True}, FULL_RESPONSE_OR_NONE)

    @property
    def sent_messages(self):
        request = {'token': self.token, 'include_received': False, 'include_sent': True}
        return send_request('messages', request, FULL_RESPONSE_OR_NONE)

    @property
    def stat(self):
        return send_request('stat', {'token': self.token}, FULL_RESPONSE_OR_NONE)


@pytest.fixture(scope="function", autouse=True)
def resetdb_fixture(request):
    resetdb()
    for user in initial_users:
        assert register(user)

    def teardown():
        resetdb()

    request.addfinalizer(teardown)


def setup_module():
    resetdb()


def teardown_module():
    resetdb()


def test_garbage_in_request():
    try:
        response = requests.put(restapi_url('login'), data=b'garbage').json()
    except ValueError:
        assert False

    assert 'status' in response
    assert response['status'] == 'failed'


def test_login_logout():
    for user in initial_users:
        token = login(user['username'], user['password'])
        assert token is not None
        assert logout(token)


def test_login_non_existing_user():
    assert login('non', 'existing') is None


def test_login_multiple_logins():
    user = initial_users[0]
    tokens = set()
    for _ in range(10):
        tokens.add(login(user['username'], user['password']))
    assert len(tokens) == 10
    for token in tokens:
        assert logout(token)


def test_login_session_count_limit():
    user = initial_users[0]
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
    user = initial_users[0]
    dates = set()
    for _ in range(10):
        sleep(0.01)
        with Session(user['username'], user['password']) as session:
            remote_user = session.usermod()
            assert remote_user is not None
            assert 'last_login' in remote_user
            dates.add(remote_user['last_login'])
    assert len(dates) == 10


def test_register():
    new_user = {'username': 'new_user',
                'password': '1234',
                'email': 'new_user@users.com',
                'real_name': '{} {}'.format(choice(first_names), choice(last_names)),
                'hobby': choice(hobbies)}

    assert register(new_user)
    assert not register(new_user)
    token = login(new_user['username'], new_user['password'])
    assert token is not None
    assert logout(token)


def test_usermod_change_user_name_forbiddance():
    user = initial_users[0]
    with Session(user['username'], user['password']) as session:
        assert session.usermod('username', 'new_user_name') is None


def test_usermod_change_password():
    user = initial_users[0]
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
    for user1, user2 in itertools.product(initial_users, initial_users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not session.add_friend(user2['username'])
            else:
                assert session.add_friend(user2['username'])
                assert not session.add_friend(user2['username'])

    for user1, user2 in itertools.product(initial_users, initial_users):
        with Session(user1['username'], user1['password']) as session:
            if user1['username'] == user2['username']:
                assert not session.del_friend(user2['username'])
            else:
                assert session.del_friend(user2['username'])
                assert not session.del_friend(user2['username'])


def test_sendmsg():
    for user1, user2 in itertools.product(initial_users, initial_users):
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
    for user in initial_users:
        with Session(user['username'], user['password']) as session:
            messages = session.messages
            assert messages is not None
            assert messages['status'] == 'ok'
            messages = messages['messages']
            assert len(messages) == 2 * (len(initial_users) - 1)
            for message in messages:
                assert message['content'] == 'message'


def test_limit_message_count():
    user1 = initial_users[0]
    user2 = initial_users[1]
    with Session(user1['username'], user1['password']) as session1, \
            Session(user2['username'], user2['password']) as session2:
        assert session1.add_friend(user2['username'])
        assert session2.add_friend(user1['username'])
        for _ in range(1100):
            assert session2.sendmsg(user1['username'], 'Message')
        assert len(session1.messages['messages']) == 1000
        assert len(session2.sent_messages['messages']) == 1000


def test_users():
    cur_user = initial_users[0]
    semi_friend = initial_users[1]
    complete_friend = initial_users[2]
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
    assert real_usernames == set([user['username'] for user in initial_users])


def test_friends():
    cur_user = initial_users[0]
    semi_friend = initial_users[1]
    complete_friend = initial_users[2]

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


def test_stat():
    user1 = initial_users[0]
    user2 = initial_users[1]
    with Session(user1['username'], user1['password']) as session1, \
            Session(user2['username'], user2['password']) as session2:
        for session in session1, session2:
            assert session.stat['messages_received'] == 0
            assert session.stat['messages_unread'] == 0
            assert session.stat['messages_sent'] == 0
            assert session.stat['friend_count'] == 0
            assert session.stat['login_count'] == 1
        assert session1.add_friend(user2['username'])
        assert session2.add_friend(user1['username'])
        for session in session1, session2:
            assert session.stat['friend_count'] == 1
        for i in range(100):
            assert session1.sendmsg(user2['username'], str(i))
            assert session2.sendmsg(user1['username'], str(i))
        for session in session1, session2:
            assert session.stat['messages_received'] == 100
            assert session.stat['messages_unread'] == 100
            assert session.stat['messages_sent'] == 100
            assert session.stat['friend_count'] == 1
            assert session.stat['login_count'] == 1
    for i in range(100):
        with Session(user1['username'], user1['password']) as session1, \
                Session(user2['username'], user2['password']) as session2:
            for session in session1, session2:
                assert session.stat['login_count'] == i + 2
    with Session(user1['username'], user1['password']) as session1, \
            Session(user2['username'], user2['password']) as session2:
        for i in range(100):
            for session in session1, session2:
                messages = session.messages['messages']
                assert len(messages) == 100 - i
                message = messages[0]
                assert message['content'] == str(99 - i)
                assert session.stat['messages_unread'] == 100 - i
                assert session.mark_as_read(message)
                assert session.stat['messages_received'] == 100
                assert session.stat['messages_unread'] == 99 - i
                assert session.stat['messages_sent'] == 100
        for i in range(100):
            for session in session1, session2:
                all_messages = session.all_messages['messages']
                assert len(all_messages) == 100
                assert session.stat['messages_unread'] == i
                message = all_messages[99 - i]
                assert session.mark_as_unread(message)
                messages = session.messages['messages']
                assert len(messages) == 1 + i
                message = messages[0]
                assert message['content'] == str(i)
                assert session.stat['messages_received'] == 100
                assert session.stat['messages_unread'] == 1 + i
                assert session.stat['messages_sent'] == 100


def concurrent_session_routine(user):
    with Session(user['username'], user['password']) as session:
        friends = initial_users[:]
        index = friends.index(user)
        del friends[index]
        for _ in range(10):
            for friend in friends:
                assert session.sendmsg(friend['username'], 'message')


def test_concurrent_sessions():
    for user1, user2 in itertools.permutations(initial_users, 2):
        with Session(user1['username'], user1['password']) as session:
            assert session.add_friend(user2['username'])

    pool = Pool(8)
    pool.map(concurrent_session_routine, initial_users * 10)

    for user in initial_users:
        with Session(user['username'], user['password']) as session:
            messages = session.messages['messages']
            assert len(messages) == 400


def exit_failed(message):
    print(message)
    sys.exit(1)


def process_command(args, username, password):
    if args.command == 'register':
        if register({'username': username, 'password': password}):
            print('User "{}" has been successfully registered.'.format(username))
        else:
            exit_failed('Failed to register a new user.')
        return

    with Session(username, password) as session:
        if args.command == 'addfriend':
            if session.add_friend(args.friend_username):
                print('User "{}" has been added to friends.'.format(args.friend_username))
            else:
                exit_failed('Failed to add user "{}" to friends.'.format(args.friend_username))
        elif args.command == 'delfriend':
            if session.del_friend(args.friend_username):
                print('User "{}" has been delete from friends.'.format(args.friend_username))
            else:
                exit_failed('Failed to delete user "{}" from friends.'.format(args.friend_username))
        elif args.command == 'sendmsg':
            if session.sendmsg(args.recipient, args.content):
                print('Message has been successfully sent to "{}".'.format(args.recipient))
            else:
                exit_failed('Failed to send a message to "{}"'.format(args.recipient))
        elif args.command == 'messages':
            for message in session.messages['messages']:
                print('| {from: <10} | {to: <10} | {datetime: <23} | {content}'.format(**message))
        elif args.command == 'stat':
            template = '{username: <10} | {last_login: <23} | {login_count: <3} | ' \
                       '{friend_count: <3}| {messages_unread: <3}'
            if args.extra:
                template += ' | {messages_received: <3} | {messages_sent: <3}'
            print(template.format(username=username, **session.stat))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fictional goggles spider.')
    parser.add_argument('--host', type=str, default='localhost', help='server host')
    parser.add_argument('--port', type=str, default='80', help='server port')
    parser.add_argument('-c', '--command', type=str, required=True,
                        choices=['register', 'addfriend', 'delfriend', 'sendmsg', 'messages', 'stat'],
                        help='command to perform')
    parser.add_argument('-u', '--username', action='append', type=str, required=True)
    parser.add_argument('-p', '--password', action='append', type=str, required=True)
    parser.add_argument('-f', '--friend_username', type=str,
                        help='username to add/delete to/from friends, '
                             'required when command "addfriend" or "delfriend" is used')
    parser.add_argument('-r', '--recipient', type=str,
                        help='recipient username, required when command "sendmsg" is used')
    parser.add_argument('-m', '--content', type=str,
                        help='message content to send, required when command "sendmsg" is used')
    parser.add_argument('-e', '--extra', action='store_true',
                        help='dump extra information, can be used with the "stat" command')

    args = parser.parse_args()

    if len(args.username) != len(args.password):
        exit_failed('You must pass the same count of the "username" and "password" arguments.')

    if args.command in ('addfriend', 'delfriend') and args.friend_username is None:
        exit_failed('Missing required argument --friend_username.')

    if args.command == 'sendmsg' and (args.recipient is None or args.content is None):
        exit_failed('Missing required argument --recipient or --content.')

    hostname = '{}:{}'.format(args.host, args.port)
    restapi_base_url = 'http://{}/restapi'.format(hostname)

    if args.command == 'messages':
        print('| {: <10} | {: <10} | {: <23} | {}'.format('From', 'To', 'Date', 'Content'))

    for username, password in zip(args.username, args.password):
        try:
            process_command(args, username, password)
        except (Exception, AssertionError) as e:
            exit_failed('Some error occured. Check arguments you have provided.')
