from hashlib import md5
from pymongo import MongoClient
from pprint import pprint

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts
messages_db = mongo_client.messages.posts


def user(i):
    return {'username': 'user{}'.format(i),
            'password': default_password,
            'email': 'user{}@users.com'.format(i),
            'last_login': 'never'}


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


if __name__ == '__main__':
    initdb(False)
