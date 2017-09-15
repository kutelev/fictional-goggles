import requests

from os import getenv

TRUE_OR_FALSE = 0
FULL_RESPONSE_OR_NONE = 1
TOKEN_OR_NONE = 2


class Session:
    hostname = getenv('FRICTIONAL_GOGGLES_IP', 'localhost:8081')
    restapi_base_url = 'http://{}/restapi'.format(hostname)

    def __init__(self, user):
        assert 'username' in user
        assert 'password' in user
        self.user = user
        self.username = user['username']
        self.token = None

    def __enter__(self):
        self.token = Session.login(self.user['username'], self.user['password'])
        assert self.token
        return self

    def __exit__(self, type, value, traceback):
        assert Session.logout(self.token)
        self.token = None

    @staticmethod
    def restapi_url(call):
        return '{}/{}'.format(Session.restapi_base_url, call)

    @staticmethod
    def send_request(call_name, request, ret_type=TRUE_OR_FALSE):
        response = requests.put(Session.restapi_url(call_name), json=request).json()

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

    @staticmethod
    def resetdb():
        return Session.send_request('resetdb', {'magic_key': 'c4f1571a-9450-11e7-a0a6-0b95339866a9'})

    @staticmethod
    def register(user):
        return Session.send_request('register', user)

    @staticmethod
    def login(username, password):
        return Session.send_request('login', {'username': username, 'password': password}, TOKEN_OR_NONE)

    @staticmethod
    def logout(token):
        return Session.send_request('logout', {'token': token})

    def usermod(self, key=None, new_value=None):
        request = {'token': self.token}

        if key is not None:
            request[key] = new_value

        return Session.send_request('usermod', request, FULL_RESPONSE_OR_NONE)

    @property
    def users(self):
        return Session.send_request('users', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    def add_friend(self, friend):
        return Session.send_request('addfriend', {'token': self.token, 'friend_username': friend['username']})

    def del_friend(self, friend):
        return Session.send_request('delfriend', {'token': self.token, 'friend_username': friend['username']})

    @property
    def friends(self):
        return Session.send_request('friends', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    def sendmsg(self, recipient, content):
        request = {'token': self.token, 'recipient': recipient['username'], 'content': content}
        return Session.send_request('sendmsg', request)

    def mark_as_read(self, message):
        request = {'token': self.token, 'message_id': message['_id'], 'action': 'mark_as_read'}
        return Session.send_request('msgmod', request)

    def mark_as_unread(self, message):
        request = {'token': self.token, 'message_id': message['_id'], 'action': 'mark_as_unread'}
        return Session.send_request('msgmod', request)

    @property
    def messages(self):
        """
        Retrieve unread messages from the inbox.
        """
        return Session.send_request('messages', {'token': self.token}, FULL_RESPONSE_OR_NONE)

    @property
    def all_received_messages(self):
        """
        Retrieve all received messages including marked as read.
        """
        return Session.send_request('messages', {'token': self.token, 'include_read': True}, FULL_RESPONSE_OR_NONE)

    @property
    def sent_messages(self):
        """
        Retrieve sent messages.
        """
        request = {'token': self.token, 'include_received': False, 'include_sent': True}
        return Session.send_request('messages', request, FULL_RESPONSE_OR_NONE)

    @property
    def all_messages(self):
        """
        Retrieve all messages, received and sent. Including already read.
        """
        request = {'token': self.token, 'include_received': True, 'include_read': True, 'include_sent': True}
        return Session.send_request('messages', request, FULL_RESPONSE_OR_NONE)

    @property
    def stat(self):
        return Session.send_request('stat', {'token': self.token}, FULL_RESPONSE_OR_NONE)
