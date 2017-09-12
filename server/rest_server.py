import codecs
import json
import re

from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, static_file, run
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from datetime import datetime
from threading import RLock

cookie_secret = 'nboitCJ05G3y80QU'

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


def get_token(func):
    def wrapper():
        if request.method == 'GET':
            token = request.get_cookie('token', secret=cookie_secret)
            data = {'token': token}
        else:
            data = json.load(utf8reader(request.body))
            if 'token' not in data:
                return failed_response
        return func(data)

    return wrapper


def not_support_get(func):
    def wrapper():
        if request.method == 'GET':
            response.headers['Content-Type'] = 'application/json'
            return failed_response
        return func()

    return wrapper


def is_username_valid(username):
    if len(username) < 3 or len(username) > 64:
        return False
    if re.match('^[a-zA-Z0-9_.-]+$', username) is None:
        return False
    return True


is_password_valid = is_username_valid


def is_real_name_valid(real_name):
    if len(real_name) > 64:
        return False
    if re.match('^[a-zA-Z0-9_. -]+$', real_name) is None:
        return False
    return True


is_hobby_valid = is_real_name_valid


def is_email_valid(email):
    if len(email) == 0:
        return True
    if len(email) < 5 or len(email) > 64:
        return False
    if re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email) is None:
        return False
    return True


# For testing purposes only
@route('/restapi/resetdb', method='PUT')
def restapi_resetdb():
    ok_response = {'status': 'ok'}
    data = json.load(utf8reader(request.body))
    if 'magic_key' not in data or data['magic_key'] != 'c4f1571a-9450-11e7-a0a6-0b95339866a9':
        return failed_response

    users_db.delete_many({})
    friends_db.delete_many({})
    messages_db.delete_many({})

    return ok_response


# For testing purposes only
@route('/restapi/shutdown', method='PUT')
def restapi_shutdown():
    ok_response = {'status': 'ok'}
    data = json.load(utf8reader(request.body))
    if 'magic_key' not in data or data['magic_key'] != '72a8f4e6-95e4-11e7-92f1-037910ef45f9':
        return failed_response

    import subprocess
    subprocess.check_call(['nginx', '-s', 'quit'])

    return ok_response


@route('/restapi/', method=['GET'])
def restapi():
    return static_file('documentation.html', root='.')


@route('/restapi/register', method=['GET', 'PUT'])
@not_support_get
def restapi_login():
    ok_response = {'status': 'ok'}

    data = json.load(utf8reader(request.body))

    if {'username', 'password'} - set(data.keys()):
        return failed_response

    known_fields = {'username', 'password', 'email', 'real_name', 'hobby'}

    if set(data.keys()) - known_fields:
        return failed_response

    user = {key: '' for key in known_fields}

    for key, value in data.items():
        user[key] = str(value)

    # Not safe at all, but still better than raw passwords
    user['password'] = md5(user['password'].encode()).hexdigest()
    user['last_login'] = 'never'
    user['login_count'] = 0

    if not is_username_valid(user['username']) or not is_password_valid(user['password']):
        return failed_response

    cursor = users_db.find({'username': user['username']})
    if cursor.count() != 0:
        return failed_response

    user_id = users_db.insert_one(user)

    cursor = users_db.find({'username': user['username']})
    if cursor.count() != 1:
        users_db.delete_one({'_id': user_id})
        return failed_response

    response.headers['Content-Type'] = 'application/json'
    return ok_response


@route('/restapi/login', method=['GET', 'PUT'])
@not_support_get
def restapi_login():
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
    user['login_count'] = user['login_count'] + 1
    users_db.update_one({'_id': user['_id']}, {"$set": user}, upsert=False)

    response.headers['Content-Type'] = 'application/json'
    auth_token = str(uuid4())
    active_sessions.register_new_session(auth_token, username)
    ok_response['token'] = auth_token
    return ok_response


@route('/restapi/logout', method=['GET', 'PUT'])
@not_support_get
def restapi_logout():
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
@get_token
def restapi_checkauth(data):
    ok_response = {'status': 'ok'}

    token = data.pop('token')

    if not active_sessions.is_session_alive(token):
        return failed_response

    response.headers['Content-Type'] = 'application/json'
    return ok_response


@route('/restapi/usermod', method=['GET', 'PUT'])
@get_token
def restapi_usermod(data):
    ok_response = {'status': 'ok'}

    dump_only = True if len(data) == 1 else False

    token = data.pop('token')
    data.pop('_id', None)
    data.pop('username', None)
    data.pop('last_login', None)
    data.pop('login_count', None)

    if 'password' in data:
        # Not safe at all, but still better than raw passwords
        data['password'] = md5(data['password'].encode()).hexdigest()

    if 'password' in data and not is_password_valid(data['password']):
        return failed_response

    if 'real_name' in data and not is_real_name_valid(data['real_name']):
        return failed_response

    if 'email' in data and not is_email_valid(data['email']):
        return failed_response

    if 'hobby' in data and not is_hobby_valid(data['hobby']):
        return failed_response

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
@not_support_get
def restapi_addfriend():
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
@not_support_get
def restapi_delfriend():
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
@not_support_get
def restapi_sendmsg():
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


@route('/restapi/msgmod', method=['GET', 'PUT'])
@not_support_get
def restapi_msgmod():
    ok_response = {'status': 'ok'}

    data = json.load(utf8reader(request.body))

    if {'token', 'message_id', 'action'} - set(data.keys()):
        return failed_response

    token = data['token']
    message_id = data['message_id']
    action = data['action']

    active_sessions.lock()
    if not active_sessions.is_session_alive(token):
        active_sessions.unlock()
        return failed_response

    username = active_sessions.get_username(token)
    active_sessions.unlock()

    if action not in ('mark_as_read', 'mark_as_unread'):
        return failed_response

    cursor = messages_db.find({'_id': ObjectId(message_id)})
    if cursor.count() != 1:
        return failed_response

    message = cursor[0]

    if action == 'mark_as_read' and message['read']:
        return failed_response

    if action == 'mark_as_unread' and not message['read']:
        return failed_response

    if action in ('mark_as_read', 'mark_as_unread'):
        message['read'] = True if action == 'mark_as_read' else False

    cursor = messages_db.find({'_id':  ObjectId(message_id)})
    if cursor.count() != 1:
        return failed_response

    if cursor[0]['to'] != username:
        return failed_response

    messages_db.update_one({'_id':  ObjectId(message_id)}, {"$set": message}, upsert=False)

    return ok_response


@route('/restapi/users', method=['GET', 'PUT'])
@get_token
def restapi_users(data):
    ok_response = {'status': 'ok'}

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
@get_token
def restapi_friends(data):
    ok_response = {'status': 'ok'}

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
        user_pair = {'username': user['friend_username'], 'friend_username': username}
        if friends_db.find(user_pair).count() == 1:
            is_friend = 2  # Complete friend
        friends.append({'username': user['friend_username'], 'is_friend': is_friend})

    ok_response['friends'] = friends

    return ok_response


@route('/restapi/messages', method=['GET', 'PUT'])
@get_token
def restapi_messages(data):
    ok_response = {'status': 'ok'}

    token = data.pop('token')
    include_read = data.pop('include_read', False)
    include_received = data.pop('include_received', True)
    include_sent = data.pop('include_sent', False)

    if not include_received and not include_sent:
        return failed_response

    active_sessions.lock()
    if not active_sessions.is_session_alive(token):
        active_sessions.unlock()
        return failed_response

    username = active_sessions.get_username(token)
    active_sessions.unlock()

    messages = []

    if include_received:
        cursor = messages_db.find({'to': username}).sort('datetime', DESCENDING).limit(1000)
        for message in cursor:
            if not include_read and message['read']:
                continue
            message['_id'] = str(message['_id'])
            messages.append(message)

    if include_sent:
        cursor = messages_db.find({'from': username}).sort('datetime', DESCENDING).limit(1000)
        for message in cursor:
            message.pop('_id')
            message.pop('read')
            messages.append(message)

    ok_response['messages'] = messages

    return ok_response


@route('/restapi/stat', method=['GET', 'PUT'])
@get_token
def restapi_stat(data):
    ok_response = {'status': 'ok'}

    token = data.pop('token')

    active_sessions.lock()
    if not active_sessions.is_session_alive(token):
        active_sessions.unlock()
        return failed_response

    username = active_sessions.get_username(token)
    active_sessions.unlock()

    cursor = users_db.find({'username': username})
    if cursor.count() != 1:
        return failed_response

    user = cursor[0]

    cursor = friends_db.find({'username': username})
    friends = []
    for friend in cursor:
        is_friend = 1
        user_pair = {'username': friend['friend_username'], 'friend_username': username}
        if friends_db.find(user_pair).count() == 1:
            is_friend = 2  # Complete friend
        friends.append({'username': friend['friend_username'], 'is_friend': is_friend})

    ok_response['messages_received'] = messages_db.find({'to': username}).count()
    ok_response['messages_unread'] = messages_db.find({'to': username, 'read': False}).count()
    ok_response['messages_sent'] = messages_db.find({'from': username}).count()
    ok_response['friend_count'] = len(friends)
    ok_response['last_login'] = user['last_login']
    ok_response['login_count'] = user['login_count']

    return ok_response


run(host='', port=8081)
