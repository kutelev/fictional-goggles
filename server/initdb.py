from hashlib import md5
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, OperationFailure
from pprint import pprint
from time import sleep
from random import choice

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts
messages_db = mongo_client.messages.posts

first_names = ['Vasiliy', 'Anatoly', 'Alexandr', 'Alexey', 'Pert', 'Vladimir', 'Ilya', 'Innokentiy']
last_names = ['Ivanov', 'Sidorov', 'Petrov', 'Maksimov', 'Kozlov', 'Popov']
hobbies = ['Screaming', 'Yelling', 'Dancing', 'Drilling', 'Singing', 'Swimming', 'Flying']

while True:
    try:
        mongo_client.admin.command('ismaster')
        break
    except ConnectionFailure:
        sleep(1)
        continue


def user(i):
    return {'username': 'user{}'.format(i),
            'password': default_password,
            'email': 'user{}@users.com'.format(i),
            'last_login': 'never',
            'real_name': '{} {}'.format(choice(first_names), choice(last_names)),
            'hobby': choice(hobbies)}


default_password = md5('1234'.encode()).hexdigest()
initial_users = [user(i) for i in range(1, 6)]


def initdb(silent=True):
    for db in (users_db, friends_db, messages_db):
        result = db.delete_many({})
        if not silent:
            print('{} document(s) has/have been deleted from the database.'.format(result.deleted_count))

    users_db.insert_many(initial_users)

    if silent:
        return

    print('The database has been initialized with following users:')
    for post in users_db.find():
        pprint(post)

    try:
        messages_db.drop_indexes()
    except OperationFailure:
        pass

    messages_db.create_index([('datetime', DESCENDING)])

if __name__ == '__main__':
    initdb(False)
