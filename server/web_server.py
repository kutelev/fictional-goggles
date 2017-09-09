import requests
from bottle import route, request, response, redirect, run, SimpleTemplate


cookie_secret = 'nboitCJ05G3y80QU'

login_form_template = \
    SimpleTemplate('<html><head><title>Fictional goggles : Login page</title>'
                   '<style>table { margin-left: auto; margin-right: auto; } body { text-align: center; }</style>'
                   '</head><body>{{message}}'
                   '<form action="/login" method="post"><table>'
                   '<tr><td>Username:</td><td><input name="username" type="text" /></td></tr>'
                   '<tr><td>Password:</td><td><input name="password" type="password" /></td></tr>'
                   '<tr><td colspan="2" style="text-align: center;"><input value="Login" type="submit" /></td></tr>'
                   '</table></form></body></html>')

main_page_template = \
    SimpleTemplate('<html><head><title>Fictional goggles : {{sub_page_name}}</title><style>'
                   'table { margin-left: auto; margin-right: auto; } '
                   'body { margin: 10px; margin-top: 50px; } '
                   'div.menu { width:100%; height:30px; margin: 10px; display:block; '
                   'position:fixed; top:0; left:0; background-color: #aaffffff; } '
                   'a { margin-left: 10px; margin-right: 10px; }'
                   '</style></head><body>'
                   '<div class="menu">'
                   '<a href="/">Home</a>'
                   '<a href="/profile">Profile</a>'
                   '<a href="/logout">Logout</a>'
                   '</div>'
                   '{{!body}}</body></html>')

profile_table_template = \
    SimpleTemplate('<center>{{message}}</center>'
                   '<form action="/profile" method="post"><table>'
                   '<tr><td>Username:</td>'
                   '<td><input name="username" value="{{username}}" type="text" readonly /></td></tr>'
                   '<tr><td>Password:</td><td><input name="password" type="password" /></td></tr>'
                   '<tr><td>Email:</td><td><input name="email" value="{{email}}" type="text" /></td></tr>'
                   '<tr><td colspan="2" style="text-align: center;"><input value="Update" type="submit" /></td></tr>'
                   '</table></form>')


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
    return main_page_template.render(sub_page_name='Home', body='')


@route('/profile', method=['GET', 'POST'])
@redirect_to_login_page
def profile_page():
    token = request.get_cookie('token', secret=cookie_secret)

    if request.method == 'GET':
        rest_response = requests.put('http://localhost:8081/restapi/usermod', json={'token': token}).json()

        if rest_response['status'] == 'ok':
            message = ''
            username = rest_response['username']
            email = rest_response['email']
        else:
            message = 'Error. Could not retrieve user profile from the server. Please, try to logout and then login.'
            username = ''
            email = ''
    else:
        password = request.forms.get('password')
        email = request.forms.get('email')

        rest_request = {'token': token, 'email': email}
        if password:
            rest_request['password'] = password

        rest_response = requests.put('http://localhost:8081/restapi/usermod', json=rest_request).json()
        if rest_response['status'] == 'ok':
            message = 'Your profile has been successfully updated.'
            username = rest_response['username']
            email = rest_response['email']
        else:
            message = 'Your profile has not been updated due to some issues. Please, try to logout and then login.'
            username = ''
            email = ''

    profile_table = profile_table_template.render(message=message, username=username, email=email)
    return main_page_template.render(sub_page_name='Profile', body=profile_table)


@route('/login', method=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        token = request.get_cookie('token', secret=cookie_secret)
        if is_authenticated(token):
            redirect('/')
        return login_form_template.render(message='')
    else:
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
