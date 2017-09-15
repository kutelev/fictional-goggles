import requests
import pytest
import itertools
import argparse
import sys

from time import sleep
from random import choice
from multiprocessing import Pool

from session import Session

MIN_PASSWORD_LENGTH = 3
MAX_PASSWORD_LENGTH = 64

first_names = ['Vasiliy', 'Anatoly', 'Alexandr', 'Alexey', 'Pert', 'Vladimir', 'Ilya', 'Innokentiy']
last_names = ['Ivanov', 'Sidorov', 'Petrov', 'Maksimov', 'Kozlov', 'Popov']
hobbies = ['Screaming', 'Yelling', 'Dancing', 'Drilling', 'Singing', 'Swimming', 'Flying']

valid_passwords = ['a' * MIN_PASSWORD_LENGTH, 'a' * MAX_PASSWORD_LENGTH]
invalid_passwords = ['a' * (MIN_PASSWORD_LENGTH - 1), 'a' * (MAX_PASSWORD_LENGTH + 1),
                     'invalid password', '<invalid>', '*invalid*', '%invalid%']  # 1234, True

invalid_usernames = invalid_passwords


def generate_user(i):
    return {'username': 'user{}'.format(i),
            'password': '1234',
            'email': 'user{}@users.com'.format(i),
            'real_name': '{} {}'.format(choice(first_names), choice(last_names)),
            'hobby': choice(hobbies)}


initial_users = [generate_user(i) for i in range(1, 6)]


@pytest.fixture(scope="function", autouse=True)
def resetdb_fixture(request):
    Session.resetdb()
    for user in initial_users:
        assert Session.register(user)

    def teardown():
        Session.resetdb()

    request.addfinalizer(teardown)


def setup_module():
    Session.resetdb()


def teardown_module():
    Session.resetdb()


def test_garbage_in_request():
    try:
        response = requests.put(Session.restapi_url('login'), data=b'garbage').json()
    except ValueError:
        assert False

    assert 'status' in response
    assert response['status'] == 'failed'


def test_login_logout():
    for user in initial_users:
        token = Session.login(user['username'], user['password'])
        assert token is not None
        assert Session.logout(token)


def test_login_non_existing_user():
    assert Session.login('non', 'existing') is None


def test_login_multiple_logins():
    user = initial_users[0]
    tokens = set()
    for _ in range(10):
        tokens.add(Session.login(user['username'], user['password']))
    assert len(tokens) == 10
    for token in tokens:
        assert Session.logout(token)


def test_login_session_count_limit():
    user = initial_users[0]
    tokens1 = set()
    tokens2 = set()
    for _ in range(128):
        tokens1.add(Session.login(user['username'], user['password']))
    assert len(tokens1) == 128
    for _ in range(128):
        tokens2.add(Session.login(user['username'], user['password']))
    for token in tokens1:
        assert not Session.logout(token)
    for token in tokens2:
        assert Session.logout(token)


def test_login_last_login():
    user = initial_users[0]
    dates = set()
    for _ in range(10):
        sleep(0.01)
        with Session(user) as session:
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

    assert Session.register(new_user)
    assert not Session.register(new_user)
    token = Session.login(new_user['username'], new_user['password'])
    assert token is not None
    assert Session.logout(token)


def test_register_invalid_username():
    new_user = {'username': 'new_user',
                'password': '1234',
                'email': 'new_user@users.com',
                'real_name': '{} {}'.format(choice(first_names), choice(last_names)),
                'hobby': choice(hobbies)}

    for username in invalid_usernames:
        new_user['username'] = username
        assert not Session.register(new_user)


def test_usermod_change_user_name_forbiddance():
    user = initial_users[0]
    with Session(user) as session:
        assert session.usermod('username', 'new_user_name') is None


def test_usermod_change_password():
    user = initial_users[0]
    old_password = user['password']
    new_password = old_password[::-1]
    with Session({'username': user['username'], 'password': old_password}) as session:
        assert session.usermod('password', new_password) is not None
    assert Session.login(user['username'], old_password) is None
    with Session({'username': user['username'], 'password': new_password}) as session:
        assert session.token
        assert session.usermod('password', old_password) is not None
    with Session({'username': user['username'], 'password': old_password}) as session:
        assert session.token
        for password in valid_passwords:
            assert session.usermod('password', password) is not None
        for password in invalid_passwords:
            assert session.usermod('password', password) is None


def test_add_del_friend():
    for user1, user2 in itertools.product(initial_users, initial_users):
        with Session(user1) as session:
            if user1['username'] == user2['username']:
                assert not session.add_friend(user2)
            else:
                assert session.add_friend(user2)
                assert not session.add_friend(user2)

    for user1, user2 in itertools.product(initial_users, initial_users):
        with Session(user1) as session:
            if user1['username'] == user2['username']:
                assert not session.del_friend(user2)
            else:
                assert session.del_friend(user2)
                assert not session.del_friend(user2)


def test_sendmsg():
    for user1, user2 in itertools.product(initial_users, initial_users):
        with Session(user1) as session1, Session(user2) as session2:
            if user1['username'] == user2['username']:
                assert not session1.add_friend(user2)
                assert not session1.sendmsg(user2, 'message')
            else:
                assert not session1.sendmsg(user2, 'message')
                assert not session2.sendmsg(user1, 'message')
                assert session1.add_friend(user2)
                assert not session1.sendmsg(user2, 'message')
                assert not session2.sendmsg(user1, 'message')
                assert session2.add_friend(user1)
                assert session1.sendmsg(user2, 'from: {}, to: {}'.format(user1['username'], user2['username']))
                assert session2.sendmsg(user1, 'from: {}, to: {}'.format(user2['username'], user1['username']))
                assert session1.del_friend(user2)
                assert session2.del_friend(user1)
    for user in initial_users:
        with Session(user) as session:
            messages = session.messages
            assert messages is not None
            assert messages['status'] == 'ok'
            messages = messages['messages']
            assert len(messages) == 2 * (len(initial_users) - 1)
            for message in messages:
                assert message['to'] == user['username']
                assert message['content'] == 'from: {}, to: {}'.format(message['from'], user['username'])


def test_msgmod():
    message_count = 10
    user1 = initial_users[0]
    user2 = initial_users[1]
    with Session(user1) as session1, Session(user2) as session2:
        assert session1.add_friend(user2)
        assert session2.add_friend(user1)
        for i in range(1, message_count + 1):
            assert session1.sendmsg(user2, 'Message')
            assert session2.sendmsg(user1, 'Message')
            assert len(session1.messages['messages']) == i
            assert len(session2.messages['messages']) == i
            assert len(session1.all_received_messages['messages']) == i
            assert len(session2.all_received_messages['messages']) == i
            assert len(session1.sent_messages['messages']) == i
            assert len(session2.sent_messages['messages']) == i
            assert len(session1.all_messages['messages']) == i * 2
            assert len(session2.all_messages['messages']) == i * 2
        for session, friend_session in itertools.permutations((session1, session2), 2):
            for message in session.messages['messages']:
                assert 'read' in message
                assert '_id' in message
                assert message['read'] is False
            for message in session.sent_messages['messages']:
                assert 'read' not in message
                assert '_id' not in message
            for i in range(1, message_count + 1):
                assert session.mark_as_read(session.all_received_messages['messages'][message_count - i])
                for j, message in enumerate(session.all_received_messages['messages']):
                    assert message['read'] is (True if j >= message_count - i else False)
                assert len(session.messages['messages']) == message_count - i
            len(session.messages['messages']) == 0
            len(session.all_received_messages['messages']) == message_count
            len(session.sent_messages['messages']) == message_count
            len(session.all_messages['messages']) == message_count * 2
            for message in session.all_messages['messages']:
                if message['to'] == session.username:
                    assert message['from'] == friend_session.username
                    assert 'read' in message
                    assert '_id' in message
                    assert message['read'] is True
                else:
                    assert message['to'] == friend_session.username
                    assert message['from'] == session.username
                    assert 'read' not in message
                    assert '_id' not in message


def test_limit_message_count():
    message_count = 1000
    user1 = initial_users[0]
    user2 = initial_users[1]
    with Session(user1) as session1, Session(user2) as session2:
        assert session1.add_friend(user2)
        assert session2.add_friend(user1)
        for _ in range(message_count + 100):
            assert session1.sendmsg(user2, 'Message')
            assert session2.sendmsg(user1, 'Message')
        for session in session1, session2:
            assert len(session.messages['messages']) == message_count
            assert len(session.sent_messages['messages']) == message_count
            assert len(session.all_messages['messages']) == message_count * 2


def test_users():
    cur_user = initial_users[0]
    semi_friend = initial_users[1]
    complete_friend = initial_users[2]
    real_usernames = set()
    with Session(cur_user) as session:
        assert session.add_friend(semi_friend)
        assert session.add_friend(complete_friend)
    with Session(complete_friend) as session:
        assert session.add_friend(cur_user)
    with Session(cur_user) as session:
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

    with Session(cur_user) as session:
        friends = session.friends
        assert friends is not None
        assert friends['status'] == 'ok'
        assert len(friends['friends']) == 0
        assert session.add_friend(semi_friend)
        assert session.add_friend(complete_friend)
    with Session(complete_friend) as session:
        assert session.add_friend(cur_user)
    with Session(cur_user) as session:
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
    message_count = 10
    login_count = 10
    user1 = initial_users[0]
    user2 = initial_users[1]
    with Session(user1) as session1, Session(user2) as session2:
        for session in session1, session2:
            assert session.stat['messages_received'] == 0
            assert session.stat['messages_unread'] == 0
            assert session.stat['messages_sent'] == 0
            assert session.stat['friend_count'] == 0
            assert session.stat['login_count'] == 1
        assert session1.add_friend(user2)
        assert session2.add_friend(user1)
        for session in session1, session2:
            assert session.stat['friend_count'] == 1
        for i in range(message_count):
            assert session1.sendmsg(user2, str(i))
            assert session2.sendmsg(user1, str(i))
        for session in session1, session2:
            assert session.stat['messages_received'] == message_count
            assert session.stat['messages_unread'] == message_count
            assert session.stat['messages_sent'] == message_count
            assert session.stat['friend_count'] == 1
            assert session.stat['login_count'] == 1
    for i in range(login_count):
        with Session(user1) as session1, Session(user2) as session2:
            for session in session1, session2:
                assert session.stat['login_count'] == i + 2
    with Session(user1) as session1, Session(user2) as session2:
        for i in range(message_count):
            for session in session1, session2:
                messages = session.messages['messages']
                assert len(messages) == message_count - i
                message = messages[0]
                assert message['content'] == str(message_count - 1 - i)
                assert session.stat['messages_unread'] == message_count - i
                assert session.mark_as_read(message)
                assert session.stat['messages_received'] == message_count
                assert session.stat['messages_unread'] == message_count - 1 - i
                assert session.stat['messages_sent'] == message_count
        for i in range(message_count):
            for session in session1, session2:
                all_messages = session.all_received_messages['messages']
                assert len(all_messages) == message_count
                assert session.stat['messages_unread'] == i
                message = all_messages[message_count - 1 - i]
                assert session.mark_as_unread(message)
                messages = session.messages['messages']
                assert len(messages) == 1 + i
                message = messages[0]
                assert message['content'] == str(i)
                assert session.stat['messages_received'] == message_count
                assert session.stat['messages_unread'] == 1 + i
                assert session.stat['messages_sent'] == message_count


def concurrent_session_routine(user):
    with Session(user) as session:
        friends = initial_users[:]
        friends = list(filter(lambda friend: friend['username'] != user['username'], friends))
        for _ in range(10):
            for friend in friends:
                assert session.sendmsg(friend, 'message')


def test_concurrent_sessions():
    for user1, user2 in itertools.permutations(initial_users, 2):
        with Session(user1) as session:
            assert session.add_friend(user2)

    pool = Pool(8)
    pool.map(concurrent_session_routine, initial_users * 10)

    for user in initial_users:
        with Session(user) as session:
            messages = session.messages['messages']
            assert len(messages) == 400


def exit_failed(message):
    print(message)
    sys.exit(1)


def process_command(args, username, password):
    if args.command == 'register':
        if Session.register({'username': username, 'password': password}):
            print('User "{}" has been successfully registered.'.format(username))
        else:
            exit_failed('Failed to register a new user.')
        return

    with Session({'username': username, 'password': password}) as session:
        if args.command == 'addfriend':
            if session.add_friend({'username': args.friend_username}):
                print('User "{}" has been added to friends.'.format(args.friend_username))
            else:
                exit_failed('Failed to add user "{}" to friends.'.format(args.friend_username))
        elif args.command == 'delfriend':
            if session.del_friend({'username': args.friend_username}):
                print('User "{}" has been delete from friends.'.format(args.friend_username))
            else:
                exit_failed('Failed to delete user "{}" from friends.'.format(args.friend_username))
        elif args.command == 'sendmsg':
            if session.sendmsg({'username': args.recipient}, args.content):
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

    Session.hostname = '{}:{}'.format(args.host, args.port)
    Session.restapi_base_url = 'http://{}/restapi'.format(Session.hostname)

    if args.command == 'messages':
        print('| {: <10} | {: <10} | {: <23} | {}'.format('From', 'To', 'Date', 'Content'))

    for username, password in zip(args.username, args.password):
        try:
            process_command(args, username, password)
        except (Exception, AssertionError):
            exit_failed('Some error occurred. Check arguments you have provided.')
