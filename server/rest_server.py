import codecs
import json

from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, run
from pymongo import MongoClient
from datetime import datetime
from initdb import initdb

utf8reader = codecs.getreader('utf8')

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts

authenticated_users = dict()

failed_response = {'status': 'failed'}
failed_response = json.dumps(failed_response)


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
    elif request.method == 'PUT':
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
        if user['password'] != md5(password.encode()).hexdigest():
            return failed_response

        user['last_login'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        users_db.update_one({'_id': user['_id']}, {"$set": user}, upsert=False)

        response.headers['Content-Type'] = 'application/json'
        auth_token = str(uuid4())
        authenticated_users[auth_token] = username
        ok_response['token'] = auth_token
        return ok_response


@route('/restapi/logout', method=['GET', 'PUT'])
def restapi_logout():
    if request.method == 'GET':
        return 'Not documented yet.'
    elif request.method == 'PUT':
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')

        if token not in authenticated_users:
            return failed_response

        authenticated_users.pop(token)

        response.headers['Content-Type'] = 'application/json'
        return ok_response


@route('/restapi/usermod', method=['GET', 'PUT'])
def restapi_usermod():
    if request.method == 'GET':
        return 'Not documented yet.'
    elif request.method == 'PUT':
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
            data['password'] = md5(data['password'].encode()).hexdigest()

        if (not data and not dump_only) or (token not in authenticated_users):
            return failed_response

        username = authenticated_users[token]

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
    elif request.method == 'PUT':
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data or 'friend_username' not in data:
            return failed_response

        token = data['token']

        if token not in authenticated_users:
            return failed_response

        username = authenticated_users[token]
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
    elif request.method == 'PUT':
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data or 'friend_username' not in data:
            return failed_response

        token = data['token']

        if token not in authenticated_users:
            return failed_response

        username = authenticated_users[token]
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


run(host='', port=8081)
