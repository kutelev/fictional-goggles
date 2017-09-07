import requests
from bottle import route, request, response, redirect, run, SimpleTemplate


cookie_secret = 'nboitCJ05G3y80QU'
authenticated_users = dict()

login_form_template = \
    SimpleTemplate('<html><body>{{message}}'
                   '<form action="/login" method="post">'
                   'Username: <input name="username" type="text" />'
                   'Password: <input name="password" type="password" />'
                   '<input value="Login" type="submit" />'
                   '</form></body></html>')


@route('/')
def main_page():
    auth_key = request.get_cookie('token', secret=cookie_secret)
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

    rest_response = requests.put('http://localhost:8081/restapi/login',
                                 json={'username': username, 'password': password})

    rest_response = rest_response.json()

    if rest_response['Status'] == 'Ok':
        auth_token = rest_response['Token']
        response.set_cookie('token', auth_token, secret=cookie_secret)
        redirect('/')
        return

    return login_form_template.render(message='Login failed! Username or password is incorrect.')


run(host='', port=8080)
