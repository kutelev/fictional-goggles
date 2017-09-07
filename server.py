from hashlib import md5
from uuid import uuid4
from bottle import route, request, response, redirect, run, SimpleTemplate
from pymongo import MongoClient

mongo_client = MongoClient()
users_db = mongo_client.users

cookie_secret = 'nboitCJ05G3y80QU'
authenticated_users = dict()

login_form_template = \
    SimpleTemplate('<html><body>{{message}}'
                   '<form action="/login" method="post">'
                   'Username: <input name="username" type="text" />'
                   'Password: <input name="password" type="password" />'
                   '<input value="Login" type="submit" />'
                   '</form></body></html>')


def check_login(username, password):
    cursor = users_db.posts.find({'username': username})
    if cursor.count() != 1:
        return False
    user = cursor[0]
    if user['password'] != md5(password.encode()).hexdigest():
        return False
    return True


@route('/')
def main_page():
    auth_key = request.get_cookie('auth_key', secret=cookie_secret)
    if auth_key and auth_key in authenticated_users:
        return authenticated_users[auth_key]
    redirect('/login')


@route('/login')
def login_get():
    return login_form_template.render(message='')


@route('/login', method='POST')
def login_post():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if check_login(username, password):
        auth_key = str(uuid4())
        authenticated_users[auth_key] = username
        response.set_cookie('auth_key', auth_key, secret=cookie_secret)
        redirect('/')
    else:
        return login_form_template.render(message='Login failed! Username or password is incorrect.')

run(host='192.168.200.100', port=8080)
