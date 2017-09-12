from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, OperationFailure
from pprint import pprint
from time import sleep

mongo_client = MongoClient()
users_db = mongo_client.users.posts
friends_db = mongo_client.friends.posts
messages_db = mongo_client.messages.posts
log_db = mongo_client.log.posts

while True:
    try:
        mongo_client.admin.command('ismaster')
        break
    except ConnectionFailure:
        sleep(1)
        continue


def initdb(silent=True):
    for db in (users_db, friends_db, messages_db, log_db):
        result = db.delete_many({})
        if not silent:
            print('{} document(s) has/have been deleted from the database.'.format(result.deleted_count))

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
