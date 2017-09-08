import requests
from bottle import route, request, response, redirect, run, SimpleTemplate


cookie_secret = 'nboitCJ05G3y80QU'

login_form_template = \
    SimpleTemplate('<html><body>{{message}}'
                   '<form action="/login" method="post">'
                   'Username: <input name="username" type="text" />'
                   'Password: <input name="password" type="password" />'
                   '<input value="Login" type="submit" />'
                   '</form></body></html>')


def is_authenticated(token):
    if not token:
        return False
    rest_response = requests.put('http://localhost:8081/restapi/checkauth', json={'token': token})
    rest_response = rest_response.json()
    if rest_response['status'] == 'ok':
        return True
    return False


def redirect_to_login_page(func):
    def wrapper():
        token = request.get_cookie('token', secret=cookie_secret)
        if not is_authenticated(token):
            redirect('/login')
            return
        return func()

    return wrapper


@route('/')
@redirect_to_login_page
def main_page():
    return 'Welcome'


@route('/login', method=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        token = request.get_cookie('token', secret=cookie_secret)
        if is_authenticated(token):
            redirect('/')
        return login_form_template.render(message='')
    elif request.method == 'POST':
        username = request.forms.get('username')
        password = request.forms.get('password')

        rest_response = requests.put('http://localhost:8081/restapi/login',
                                     json={'username': username, 'password': password})

        rest_response = rest_response.json()

        if rest_response['status'] == 'ok':
            auth_token = rest_response['token']
            response.set_cookie('token', auth_token, secret=cookie_secret)
            redirect('/')
            return

        return login_form_template.render(message='Login failed. Please, check your credentials.')


@route('/logout')
def logout_page():
    token = request.get_cookie('token', secret=cookie_secret)
    if is_authenticated(token):
        requests.put('http://localhost:8081/restapi/logout', json={'token': token})
    redirect('/login')


run(host='', port=8080)
