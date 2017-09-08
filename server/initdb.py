from hashlib import md5
from pymongo import MongoClient
from pprint import pprint

mongo_client = MongoClient()
users_db = mongo_client.users

result = users_db.posts.delete_many({})
print('{} document(s) has/have been deleted from the database.'.format(result.deleted_count))

default_password = md5('1234'.encode()).hexdigest()
initial_users = [{'username': 'user{}'.format(i), 'password': default_password} for i in range(1, 6)]
users_db.posts.insert_many(initial_users)

print('The database has been initialized with following users:')
for post in users_db.posts.find():
    pprint(post)
