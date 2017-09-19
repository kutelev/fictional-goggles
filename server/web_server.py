import requests
from bottle import route, request, response, redirect, run, SimpleTemplate
from urllib.parse import urlparse
from hashlib import md5


cookie_secret = 'nboitCJ05G3y80QU'

register_form_template = \
    SimpleTemplate('<html><head><title>Fictional goggles : Login page</title>'
                   '<style>table { margin-left: auto; margin-right: auto; } body { text-align: center; }</style>'
                   '</head><body><a href="/login">Login page</a><br/>{{message}}'
                   '<form action="/register" method="post"><table>'
                   '<tr><td>Username:</td><td><input name="username" type="text" /></td></tr>'
                   '<tr><td>Password:</td><td><input name="password" type="password" /></td></tr>'
                   '<tr><td colspan="2" style="text-align: center;"><input value="Register" type="submit" /></td></tr>'
                   '</table></form></body></html>')

login_form_template = \
    SimpleTemplate('<html><head><title>Fictional goggles : Login page</title>'
                   '<style>table { margin-left: auto; margin-right: auto; } body { text-align: center; }</style>'
                   '</head><body><a href="/register">Create a new account</a><br/>{{message}}'
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
                   '<a href="/inbox">Inbox (Unread)</a>'
                   '<a href="/inbox?include_read=1">Inbox (All)</a>'
                   '<a href="/sent">Sent</a>'
                   '<a href="/logout">Logout</a>'
                   '</div>'
                   '{{!body}}</body></html>')

info_table_template = \
    SimpleTemplate('<table>'
                   '<tr><th>Messages received (All / Unread):</th>'
                   '<td>{{response["messages_received"]}} / {{response["messages_unread"]}}</td></tr>'
                   '<tr><th>Messages sent:</th><td>{{response["messages_sent"]}}</td></tr>'
                   '<tr><th>Friend count:</th><td>{{response["friend_count"]}}</td></tr>'
                   '<tr><th>Last login on:</th><td>{{response["last_login"]}}</td></tr>'
                   '<tr><th>Login count:</th><td>{{response["login_count"]}}</td></tr>'
                   '</table>')

profile_table_template = \
    SimpleTemplate('<center>{{message}}</center>'
                   '<form action="/profile" method="post">'
                   '<input type="hidden" name="csrf_token" value="{{csrf_token}}"><table>'
                   '<tr><td>Username:</td>'
                   '<td><input name="username" value="{{username}}" type="text" readonly /></td></tr>'
                   '<tr><td>Real name:</td>'
                   '<td><input name="real_name" value="{{real_name}}" type="text" /></td></tr>'
                   '<tr><td>Password:</td><td><input name="password" type="password" /></td></tr>'
                   '<tr><td>Email:</td><td><input name="email" value="{{email}}" type="text" /></td></tr>'
                   '<tr><td>Hobby:</td><td><input name="hobby" value="{{hobby}}" type="text" /></td></tr>'
                   '<tr><td colspan="2" style="text-align: center;"><input value="Update" type="submit" /></td></tr>'
                   '</table></form>')


def generate_csrf_token(token):
    return md5(token.encode()).hexdigest()


def validate_csrf_token(token, csrf_token):
    return True if csrf_token == generate_csrf_token(token) else False


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


def logging(func):
    def wrapper():
        sub_page = urlparse(request.url).path[1:]
        if not sub_page:
            sub_page = 'home'
        token = request.get_cookie('token', secret=cookie_secret)
        requests.put('http://localhost:8081/restapi/log', json={'token': token, 'sub_page': sub_page}).json()
        return func()

    return wrapper


@route('/')
@redirect_to_login_page
@logging
def main_page():
    token = request.get_cookie('token', secret=cookie_secret)

    rest_response = requests.put('http://localhost:8081/restapi/stat', json={'token': token}).json()

    log_table = '<table><tr><th>Sub-page</th><th>Visit count</th></tr>{}</table>'
    row = '<tr><td>{}</td><td>{}</td></tr>'

    if rest_response['status'] == 'ok':
        body = info_table_template.render(response=rest_response)
        rows = []
        for key, value in rest_response['counters'].items():
            rows.append(row.format(key, value))
        log_table = log_table.format(''.join(rows))
        body = ''.join([body, '<center>Visit counters</center>', log_table])
    else:
        body = '<center>Failed to retrieve information from the server. ' \
               'Please, try to logout and then login.</center>'

    return main_page_template.render(sub_page_name='Home', body=body)


@route('/profile', method=['GET', 'POST'])
@redirect_to_login_page
@logging
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
        username = request.forms.username
        real_name = request.forms.real_name
        password = request.forms.password
        email = request.forms.email
        hobby = request.forms.hobby

    if request.method == 'POST' and validate_csrf_token(token, request.forms.csrf_token):
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
            username = username
            real_name = real_name
            email = email
            hobby = hobby
    elif request.method == 'POST':
        rest_response = requests.put('http://localhost:8081/restapi/usermod', json={'token': token}).json()

        if rest_response['status'] == 'ok':
            username = rest_response['username']
            real_name = rest_response['real_name']
            email = rest_response['email']
            hobby = rest_response['hobby']
        else:
            username = ''
            real_name = ''
            email = ''
            hobby = ''

        message = 'CSRF attack detected'

    profile_table = profile_table_template.render(message=message, csrf_token=generate_csrf_token(token),
                                                  username=username, real_name=real_name, email=email, hobby=hobby)
    return main_page_template.render(sub_page_name='Profile', body=profile_table)


@route('/users', method=['GET', 'POST'])
@route('/friends', method=['GET', 'POST'])
@redirect_to_login_page
@logging
def users_page():
    sub_page = request.url.split('/')[-1].split('?')[0]

    token = request.get_cookie('token', secret=cookie_secret)

    rest_response = requests.put('http://localhost:8081/restapi/usermod', json={'token': token}).json()

    if rest_response['status'] == 'ok':
        username = rest_response['username']
    else:
        message = '<center>Could not retrieve users list from the server. ' \
                  'Please, try to logout and then login.</center>'
        return main_page_template.render(sub_page_name='Users', body=message)

    if request.method == 'POST' and validate_csrf_token(token, request.forms.csrf_token):
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
    elif request.method == 'POST':
        message = 'CSRF attack detected'
    else:
        message = ''

    rest_response = requests.put('http://localhost:8081/restapi/{}'.format(sub_page), json={'token': token}).json()

    if rest_response['status'] == 'ok':
        users_table = '<center>{}</center><table><tr><th>Username</th><th>Status</th><th>Action</th></tr>{}</table>'
        rows = []
        users = rest_response[sub_page]
        row = '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'
        for user in users:
            if user['username'] == username:
                status = 'You'
                action = ''
            elif user['is_friend'] in (1, 2):
                status = 'Semi-friend' if user['is_friend'] == 1 else 'Friend'
                action = '<form action="" method="post">' \
                         '<input type="hidden" name="csrf_token" value="{}">' \
                         '<input name="delfriend" value="{}" type="hidden" />' \
                         '<input name="submit" type="submit" value="Remove from friends" />' \
                         '</form>'.format(generate_csrf_token(token), user['username'])
            else:
                status = ''
                action = '<form action="" method="post">' \
                         '<input type="hidden" name="csrf_token" value="{}">' \
                         '<input name="addfriend" value="{}" type="hidden" />' \
                         '<input name="submit" type="submit" value="Add to friends" />' \
                         '</form>'.format(generate_csrf_token(token), user['username'])
            rows.append(row.format(user['username'], status, action))
        if sub_page == 'friends' and not rows:
            users_table = '<center>{}</center><center>You have no friends.</center>'.format(message)
        else:
            users_table = users_table.format(message, ''.join(rows))
    else:
        users_table = '<center>Could not retrieve users list from the server. ' \
                      'Please, try to logout and then login.</center>'

    return main_page_template.render(sub_page_name='Users', body=users_table)


@route('/inbox', method=['GET', 'POST'])
@redirect_to_login_page
@logging
def inbox_page():
    token = request.get_cookie('token', secret=cookie_secret)

    if request.method == 'POST' and validate_csrf_token(token, request.forms.csrf_token):
        if request.forms.get('mark_as_read') or request.forms.get('mark_as_unread'):
            action = 'mark_as_read' if request.forms.get('mark_as_read') else 'mark_as_unread'
            message_id = request.forms.get(action)
            rest_request = {'token': token, 'message_id': message_id, 'action': action}
            rest_response = requests.put('http://localhost:8081/restapi/msgmod', json=rest_request).json()
            if rest_response['status'] == 'ok':
                info_message = 'Message has been successfully marked as {}.'.format(
                    'read' if action == 'mark_as_read' else 'unread')
            else:
                info_message = 'Operation failed. Please, try to logout and then login.'
        else:
            info_message = ''
    elif request.method == 'POST':
        info_message = 'CSRF attack detected'
    else:
        info_message = ''

    include_read = request.query.include_read
    include_read = True if include_read == '1' else False

    rest_request = {'token': token, 'include_read': include_read}
    rest_response = requests.put('http://localhost:8081/restapi/messages', json=rest_request).json()

    if rest_response['status'] == 'ok':
        messages_table = '<center>{}</center><table>{}</table>'

        rows = []
        messages = rest_response['messages']

        row = \
            SimpleTemplate('<tr><td>From:</td><td>{{message["from"]}}</td></tr>'
                           '<tr><td>Date:</td><td>{{message["datetime"]}}</td></tr>'
                           '<tr><td>Action:</td><td>{{!action}}</td></tr>'
                           '<tr><td colspan="2">Content:</td></tr>'
                           '<tr><td colspan="2">{{message["content"]}}</td></tr>')

        for message in messages:
            is_read = message['read']
            action = '<form action="" method="post">' \
                     '<input type="hidden" name="csrf_token" value="{}">' \
                     '<input name="{}" value="{}" type="hidden" />' \
                     '<input name="submit" type="submit" value="{}" />' \
                     '</form>'.format(generate_csrf_token(token),
                                      'mark_as_unread' if is_read else 'mark_as_read',
                                      message['_id'],
                                      'Mark as unread' if is_read else 'Mark as read')
            rows.append(row.render(message=message, action=action))

        if not rows:
            messages_table = '<center>{}</center><center>You have no messages.</center>'.format(info_message)
        else:
            messages_table = messages_table.format(info_message, ''.join(rows))
    else:
        messages_table = '<center>Could not retrieve messages from the server. ' \
                         'Please, try to logout and then login.</center>'

    return main_page_template.render(sub_page_name='Inbox', body=messages_table)


@route('/sent', method=['GET', 'POST'])
@redirect_to_login_page
@logging
def sent_page():
    def generate_friend_list(token, recipient):
        rest_response = requests.put('http://localhost:8081/restapi/friends', json={'token': token}).json()

        option = '<option value="{0}"{1}>{0}</option>'
        select = '<select name="recipient">{}</select>'

        if rest_response['status'] == 'ok':
            friends = rest_response['friends']
        else:
            friends = []

        options = []

        for friend in friends:
            if friend['is_friend'] != 2:
                continue
            options.append(option.format(friend['username'], ' selected' if friend['username'] == recipient else ''))

        if options:
            return select.format(''.join(options))
        else:
            return '<input name="recipient" value="You have no friends." type="text" readonly />'

    token = request.get_cookie('token', secret=cookie_secret)

    if request.method == 'POST' and validate_csrf_token(token, request.forms.csrf_token):
        recipient = request.forms.recipient
        content = request.forms.content
        print(content)
        rest_request = {'token': token, 'recipient': recipient, 'content': content}
        rest_response = requests.put('http://localhost:8081/restapi/sendmsg', json=rest_request).json()
        if rest_response['status'] == 'ok':
            info_message = 'Message has been successfully sent to {}.'.format(recipient)
            recipient = ''
            content = ''
        else:
            info_message = 'Operation failed. Please, try to logout and then login.'
    elif request.method == 'POST':
        recipient = ''
        content = ''
        info_message = 'CSRF attack detected'
    else:
        recipient = ''
        content = ''
        info_message = ''

    include_read = request.query.include_read
    include_read = True if include_read == '1' else False

    rest_request = {'token': token, 'include_read': include_read, 'include_received': False, 'include_sent': True}
    rest_response = requests.put('http://localhost:8081/restapi/messages', json=rest_request).json()

    if rest_response['status'] == 'ok':
        messages_table = '<center>{}</center><form action="" method="post">' \
                         '<input type="hidden" name="csrf_token" value="{}"><table>' \
                         '<tr><td>To:</td>' \
                         '<td>{}</td></tr>' \
                         '<tr><td colspan="2">Content:</td></tr>' \
                         '<tr><td colspan="2"><textarea name="content" rows="10">{}</textarea></td></tr>' \
                         '<tr><td colspan="2" style="text-align: center;">' \
                         '<input value="Send" type="submit" /></td></tr>' \
                         '</table></form>{}'

        rows = []
        messages = rest_response['messages']

        row = \
            SimpleTemplate('<tr><td>To:</td><td>{{to}}</td></tr>'
                           '<tr><td>Date:</td><td>{{datetime}}</td></tr>'
                           '<tr><td colspan="2">Content:</td></tr>'
                           '<tr><td colspan="2">{{content}}</td></tr>')

        for message in messages:
            rows.append(row.render(**message))

        if not rows:
            messages_table = messages_table.format(info_message, generate_csrf_token(token),
                                                   generate_friend_list(token, recipient),
                                                   content, '<center>You have not sent any messages.</center>')
        else:
            messages_table = messages_table.format(info_message, generate_csrf_token(token),
                                                   generate_friend_list(token, recipient),
                                                   content, '<table>{}</table>'.format(''.join(rows)))
    else:
        messages_table = '<center>Could not retrieve messages from the server. ' \
                         'Please, try to logout and then login.</center>'

    return main_page_template.render(sub_page_name='Sent', body=messages_table)


@route('/register', method=['GET', 'POST'])
def register_page():
    if request.method == 'GET':
        token = request.get_cookie('token', secret=cookie_secret)
        if is_authenticated(token):
            redirect('/')
        return register_form_template.render(message='')
    else:
        username = request.forms.get('username')
        password = request.forms.get('password')

        rest_response = requests.put('http://localhost:8081/restapi/register',
                                     json={'username': username, 'password': password})

        rest_response = rest_response.json()

        if rest_response['status'] == 'ok':
            rest_response = requests.put('http://localhost:8081/restapi/login',
                                         json={'username': username, 'password': password})

            rest_response = rest_response.json()

            if rest_response['status'] == 'ok':
                auth_token = rest_response['token']
                response.set_cookie('token', auth_token, secret=cookie_secret)
                redirect('/profile')
                return

            redirect('/login')
            return

        return register_form_template.render(message='Could not create a new account for you. '
                                                     'Please try again.')


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
