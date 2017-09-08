from hashlib import md5
from pymongo import MongoClient
from pprint import pprint

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts


def user(i):
    return {'username': 'user{}'.format(i),
            'password': default_password,
            'email': 'user{}@users.com'.format(i),
            'last_login': 'never'}


result = users_db.delete_many({})
print('{} document(s) has/have been deleted from the database.'.format(result.deleted_count))

result = friends_db.delete_many({})
print('{} document(s) has/have been deleted from the database.'.format(result.deleted_count))

default_password = md5('1234'.encode()).hexdigest()
initial_users = [user(i) for i in range(1, 6)]
users_db.insert_many(initial_users)

print('The database has been initialized with following users:')
for post in users_db.find():
    pprint(post)
