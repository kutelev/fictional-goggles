from hashlib import md5
from bottle import route, run, request
from pymongo import MongoClient

mongo_client = MongoClient()
users_db = mongo_client.users


def check_login(username, password):
    cursor = users_db.posts.find({'username': username})
    if cursor.count() != 1:
        return False
    user = cursor[0]
    if user['password'] != md5(password.encode()).hexdigest():
        return False
    return True


def login_form(failed=False):
    return '<html><body>{}' \
           '<form action="/login" method="post">' \
           'Username: <input name="username" type="text" />' \
           'Password: <input name="password" type="password" />' \
           '<input value="Login" type="submit" />' \
           '</form></body></html>'.format(
        'Login failed! Username or password is incorrect.' if failed else '')


@route('/login')
def login():
    return login_form()

@route('/login', method='POST')
def do_login():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if check_login(username, password):
        return 'Login succeeded!'
    else:
        return login_form(True)

run(host='192.168.200.100', port=8080)
