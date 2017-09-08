import codecs
import json

from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, run
from pymongo import MongoClient

utf8reader = codecs.getreader('utf8')

mongo_client = MongoClient()
users_db = mongo_client.users

authenticated_users = dict()

failed_response = {'status': 'failed'}
failed_response = json.dumps(failed_response)


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

        cursor = users_db.posts.find({'username': username})
        if cursor.count() != 1:
            return failed_response
        user = cursor[0]
        if user['password'] != md5(password.encode()).hexdigest():
            return failed_response

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
def restapi_login():
    if request.method == 'GET':
        return 'Not documented yet.'
    elif request.method == 'PUT':
        ok_response = {'status': 'ok'}

        data = json.load(utf8reader(request.body))
        if 'token' not in data:
            return failed_response

        token = data.pop('token')
        data.pop('_id', None)
        data.pop('username', None)

        if 'password' in data:
            data['password'] = md5(data['password'].encode()).hexdigest()

        if not data or token not in authenticated_users:
            return failed_response

        username = authenticated_users[token]

        cursor = users_db.posts.find({'username': username})
        if cursor.count() != 1:
            return failed_response
        user = cursor[0]

        if set(data.keys()) - set(user.keys()):
            return failed_response

        for key, value in data.items():
            user[key] = value

        users_db.posts.update_one({'_id': user['_id']}, {"$set": user}, upsert=False)

        response.headers['Content-Type'] = 'application/json'
        auth_token = str(uuid4())
        ok_response['token'] = auth_token
        return ok_response


run(host='', port=8081)
