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
                   '<a href="/users">Users</a>'
                   '<a href="/friends">Friends</a>'
                   '<a href="/logout">Logout</a>'
                   '</div>'
                   '{{!body}}</body></html>')

profile_table_template = \
    SimpleTemplate('<center>{{message}}</center>'
                   '<form action="/profile" method="post"><table>'
                   '<tr><td>Username:</td>'
                   '<td><input name="username" value="{{username}}" type="text" readonly /></td></tr>'
                   '<tr><td>Real name:</td>'
                   '<td><input name="real_name" value="{{real_name}}" type="text" /></td></tr>'
                   '<tr><td>Password:</td><td><input name="password" type="password" /></td></tr>'
                   '<tr><td>Email:</td><td><input name="email" value="{{email}}" type="text" /></td></tr>'
                   '<tr><td>Hobby:</td><td><input name="hobby" value="{{hobby}}" type="text" /></td></tr>'
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
            real_name = rest_response['real_name']
            email = rest_response['email']
            hobby = rest_response['hobby']
        else:
            message = 'Error. Could not retrieve user profile from the server. Please, try to logout and then login.'
            username = ''
            real_name = ''
            email = ''
            hobby = ''
    else:
        real_name = request.forms.get('real_name')
        password = request.forms.get('password')
        email = request.forms.get('email')
        hobby = request.forms.get('hobby')

        rest_request = {'token': token, 'real_name': real_name, 'email': email, 'hobby': hobby}
        if password:
            rest_request['password'] = password

        rest_response = requests.put('http://localhost:8081/restapi/usermod', json=rest_request).json()
        if rest_response['status'] == 'ok':
            message = 'Your profile has been successfully updated.'
            username = rest_response['username']
            real_name = rest_response['real_name']
            email = rest_response['email']
            hobby = rest_response['hobby']
        else:
            message = 'Your profile has not been updated due to some issues. Please, try to logout and then login.'
            username = ''
            real_name = ''
            email = ''
            hobby = ''

    profile_table = profile_table_template.render(message=message, username=username,
                                                  real_name=real_name, email=email, hobby=hobby)
    return main_page_template.render(sub_page_name='Profile', body=profile_table)


@route('/users', method=['GET', 'POST'])
@redirect_to_login_page
def users_page():
    token = request.get_cookie('token', secret=cookie_secret)

    rest_response = requests.put('http://localhost:8081/restapi/usermod', json={'token': token}).json()

    if rest_response['status'] == 'ok':
        username = rest_response['username']
    else:
        message = '<center>Could not retrieve users list from the server. Please, try to logout and then login.</center>'
        return main_page_template.render(sub_page_name='Users', body=message)

    if request.method == 'POST':
        if request.forms.get('addfriend') or request.forms.get('delfriend'):
            command = 'addfriend' if request.forms.get('addfriend') else 'delfriend'
            friend_username = request.forms.get(command)
            rest_response = requests.put('http://localhost:8081/restapi/{}'.format(command),
                                         json={'token': token, 'friend_username': friend_username}).json()

            if rest_response['status'] == 'ok':
                if command == 'addfriend':
                    message = 'User {} has been successfully added to your friends.'.format(friend_username)
                else:
                    message = 'User {} has been successfully removed from your friends.'.format(friend_username)
            else:
                message = 'Operation failed. Please, try to logout and then login.'
    else:
        message = ''

    rest_response = requests.put('http://localhost:8081/restapi/users', json={'token': token}).json()

    if rest_response['status'] == 'ok':
        users_table = '<center>{}</center><table><tr><th>Username</th><th>Status</th><th>Action</th></tr>{}</table>'
        rows = []
        users = rest_response['users']
        row = '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'
        for user in users:
            if user['username'] == username:
                status = 'You'
                action = ''
            elif user['is_friend'] in (1, 2):
                status = 'Semi-friend' if user['is_friend'] == 1 else 'Friend'
                action = '<form action="/users" method="post">' \
                         '<input name="delfriend" value="{}" type="hidden" />' \
                         '<input name="submit" type="submit" value="Remove from friends" />' \
                         '</form>'.format(user['username'])
            else:
                status = ''
                action = '<form action="/users" method="post">' \
                         '<input name="addfriend" value="{}" type="hidden" />' \
                         '<input name="submit" type="submit" value="Add to friends" />' \
                         '</form>'.format(user['username'])
            rows.append(row.format(user['username'], status, action))
        users_table = users_table.format(message, ''.join(rows))
    else:
        users_table = '<center>Could not retrieve users list from the server. Please, try to logout and then login.</center>'

    return main_page_template.render(sub_page_name='Users', body=users_table)


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
