import argparse
import sys

from session import Session

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
