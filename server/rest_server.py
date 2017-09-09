import codecs
import json

from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, run
from pymongo import MongoClient
from datetime import datetime
from threading import RLock
from initdb import initdb

utf8reader = codecs.getreader('utf8')

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts
messages_db = mongo_client.messages.posts


class ActiveSessions:
    def __init__(self):
        self.mutex = RLock()
        self.sessions = dict()
        self.user_sessions = dict()

    def register_new_session(self, token, username):
        with self.mutex:
            self.sessions[token] = username
            if username not in self.user_sessions:
                self.user_sessions[username] = []
            self.user_sessions[username].append(token)
            if len(self.user_sessions[username]) > 128:
                self.sessions.pop(self.user_sessions[username][0])
                self.user_sessions[username] = self.user_sessions[username][1::]
            pass

    def unregister_session(self, token):
        with self.mutex:
            username = self.sessions.pop(token, None)
            if username is not None:
                index = self.user_sessions[username].index(token)
                del self.user_sessions[username][index]

    def is_session_alive(self, token):
        with self.mutex:
            return True if token in self.sessions else False

    def get_username(self, token):
        return self.sessions[token]

    def lock(self):
        self.mutex.acquire()

    def unlock(self):
        self.mutex.release()


active_sessions = ActiveSessions()

failed_response = {'status': 'failed'}
failed_response = json.dumps(failed_response)


def cur_datetime():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


# For testing purposes only
@route('/restapi/resetdb', method='PUT')
def restapi_resetdb():
    ok_response = {'status': 'ok'}
    data = json.load(utf8reader(request.body))
    if 'magic_key' not in data or data['magic_key'] != 'c4f1571a-9450-11e7-a0a6-0b95339866a9':
        return failed_response

    initdb()
    return ok_response


@route('/restapi/login', method=['GET', 'PUT'])
def restapi_login():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'username' not in data or 'password' not in data:
            return failed_response

        username = data['username']
        password = data['password']

        cursor = users_db.find({'username': username})
        if cursor.count() != 1:
            return failed_response
        user = cursor[0]
        # Not safe at all, but still better than raw passwords
        if user['password'] != md5(password.encode()).hexdigest():
            return failed_response

        user['last_login'] = cur_datetime()
        users_db.update_one({'_id': user['_id']}, {"$set": user}, upsert=False)

        response.headers['Content-Type'] = 'application/json'
        auth_token = str(uuid4())
        active_sessions.register_new_session(auth_token, username)
        ok_response['token'] = auth_token
        return ok_response


@route('/restapi/logout', method=['GET', 'PUT'])
def restapi_logout():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        active_sessions.unregister_session(token)
        active_sessions.unlock()

        response.headers['Content-Type'] = 'application/json'
        return ok_response


@route('/restapi/checkauth', method=['GET', 'PUT'])
def restapi_checkauth():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')

        if not active_sessions.is_session_alive(token):
            return failed_response

        response.headers['Content-Type'] = 'application/json'
        return ok_response


@route('/restapi/usermod', method=['GET', 'PUT'])
def restapi_usermod():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        dump_only = True if len(data) == 1 else False

        token = data.pop('token')
        data.pop('_id', None)
        data.pop('username', None)
        data.pop('last_login', None)

        if 'password' in data:
            # Not safe at all, but still better than raw passwords
            data['password'] = md5(data['password'].encode()).hexdigest()

        active_sessions.lock()
        if (not data and not dump_only) or (not active_sessions.is_session_alive(token)):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        cursor = users_db.find({'username': username})
        if cursor.count() != 1:
            return failed_response
        user = cursor[0]

        if set(data.keys()) - set(user.keys()):
            return failed_response

        for key, value in data.items():
            user[key] = value

        users_db.update_one({'_id': user['_id']}, {"$set": user}, upsert=False)

        user.pop('_id', None)
        user.pop('password', None)

        for key, value in user.items():
            ok_response[key] = value

        response.headers['Content-Type'] = 'application/json'
        return ok_response


@route('/restapi/addfriend', method=['GET', 'PUT'])
def restapi_addfriend():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data or 'friend_username' not in data:
            return failed_response

        token = data['token']

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        friend_username = data['friend_username']

        if username == friend_username:
            return failed_response

        cursor = users_db.find({'username': friend_username})
        if cursor.count() != 1:
            return failed_response

        friends = {'username': username, 'friend_username': friend_username}

        cursor = friends_db.find(friends)
        if cursor.count() == 1:
            return failed_response

        friends_db.insert_one(friends)
        return ok_response


@route('/restapi/delfriend', method=['GET', 'PUT'])
def restapi_delfriend():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data or 'friend_username' not in data:
            return failed_response

        token = data['token']

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        friend_username = data['friend_username']

        cursor = users_db.find({'username': friend_username})
        if cursor.count() != 1:
            return failed_response

        friends = {'username': username, 'friend_username': friend_username}

        cursor = friends_db.find(friends)
        if cursor.count() == 0:
            return failed_response

        friends_db.delete_one(friends)
        return ok_response


@route('/restapi/sendmsg', method=['GET', 'PUT'])
def restapi_sendmsg():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))

        if {'token', 'recipient', 'content'} - set(data.keys()):
            return failed_response

        token = data['token']

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        recipient_username = data['recipient']
        content = data['content']

        if username == recipient_username:
            return failed_response

        if len(content) > 1024:
            return failed_response

        cursor = users_db.find({'username': recipient_username})
        if cursor.count() != 1:
            return failed_response

        for username1, username2 in ((username, recipient_username), (recipient_username, username)):
            user_pair = {'username': username1, 'friend_username': username2}
            cursor = friends_db.find(user_pair)
            if cursor.count() != 1:
                return failed_response

        message = {'from': username,
                   'to': recipient_username,
                   'content': content,
                   'datetime': cur_datetime(),
                   'read': False}

        messages_db.insert_one(message)
        return ok_response


@route('/restapi/users', method=['GET', 'PUT'])
def restapi_users():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        cursor = users_db.find({})
        users = []
        for user in cursor:
            is_friend = 0
            user_pair = {'username': username, 'friend_username': user['username']}
            if friends_db.find(user_pair).count() == 1:
                is_friend = 1  # Semi-friend
                user_pair = {'username': user['username'], 'friend_username': username}
                if friends_db.find(user_pair).count() == 1:
                    is_friend = 2  # Complete friend
            users.append({'username': user['username'], 'is_friend': is_friend})

        ok_response['users'] = users

        return ok_response


@route('/restapi/friends', method=['GET', 'PUT'])
def restapi_friends():
    if request.method == 'GET':
        return 'Not documented yet.'
    else:
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')

        active_sessions.lock()
        if not active_sessions.is_session_alive(token):
            active_sessions.unlock()
            return failed_response

        username = active_sessions.get_username(token)
        active_sessions.unlock()

        cursor = friends_db.find({'username': username})
        friends = []
        for user in cursor:
            is_friend = 1
            user_pair = {'username': user['username'], 'friend_username': username}
            if friends_db.find(user_pair).count() == 1:
                is_friend = 2  # Complete friend
            friends.append({'username': user['username'], 'is_friend': is_friend})

        ok_response['friends'] = friends

        return ok_response


run(host='', port=8081)
