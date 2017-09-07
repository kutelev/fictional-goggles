import codecs
import json

from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, run
from pymongo import MongoClient

utf8reader = codecs.getreader('utf8')

mongo_client = MongoClient()
users_db = mongo_client.users


@route('/restapi/login', method=['GET', 'PUT'])
def restapi_login():
    if request.method == 'GET':
        return 'Not documented yet.'
    elif request.method == 'PUT':
        ok_response = {'Status': 'Ok'}
        failed_response = {'Status': 'Failed'}

        data = json.load(utf8reader(request.body))
        if 'username' not in data or 'password' not in data:
            return json.dumps(failed_response)

        username = data['username']
        password = data['password']

        cursor = users_db.posts.find({'username': username})
        if cursor.count() != 1:
            return json.dumps(failed_response)
        user = cursor[0]
        if user['password'] != md5(password.encode()).hexdigest():
            return json.dumps(failed_response)

        response.headers['Content-Type'] = 'application/json'
        auth_token = str(uuid4())
        ok_response['Token'] = auth_token
        return ok_response


run(host='', port=8081)
