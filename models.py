from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.json_util import dumps
from flask_login import UserMixin
from config import ConfigDB
import json

client = MongoClient(ConfigDB.MONGODB_URI)
db = client[ConfigDB.MONGO_DBNAME]
users_collection = db.users
data_collection = db.data

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['_id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.role = user_data['role']

    @staticmethod
    def from_document(doc):
        if doc:
            return User(doc)
        return None


def find_user(username):
    user_data = users_collection.find_one({'username': username})
    return User.from_document(user_data)


def find_user_by_id(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User.from_document(user_data)


def add_user(username, password, collections, role):
    if not find_user(username):
        password_hash = generate_password_hash(password)
        if role == 'admin':
            collections = 'all'
        users_collection.insert_one({'username': username, 'password_hash': password_hash, 'collections':collections, 'role':role})
        return True
    return False


def get_all_users():
    user_docs = users_collection.find()
    users = [User.from_document(doc) for doc in user_docs]
    return users


def remove_user_by_name(username):
    if username != 'admin':
        query = {'username': username}
        users_collection.delete_one(query)
        return True
    return False


def check_password(user, password):
    return check_password_hash(user.password_hash, password)


def get_db_collection_names():
    collections = db.list_collection_names()
    return collections


def extract_db_collection(path, collection_name, chunk_size=1000):
    """
    Extracts the data from the specified MongoDB collection and writes it to a JSON file in chunks.
    chunk_size (int): The number of documents to process in each chunk. Default is 1000.
    """
    with open(path, 'w') as file:
        file.write('[')  # Start the JSON array
        cursor = db[collection_name].find()
        first = True
        while True:
            chunk = []
            for _ in range(chunk_size):
                try:
                    chunk.append(next(cursor))
                except StopIteration:
                    break
            if not chunk:
                break
            if not first:
                file.write(', ')
            else:
                first = False
            file.write(dumps(chunk)[1:-1])  # Remove the surrounding square brackets
        file.write(']')  # End the JSON array


def convert_oid(item):
    if isinstance(item, dict):
        for key, value in item.items():
            if isinstance(value, dict) and '$oid' in value:
                item[key] = ObjectId(value['$oid'])
            else:
                convert_oid(value)
    elif isinstance(item, list):
        for i in range(len(item)):
            item[i] = convert_oid(item[i])
    return item


def rename_collection_if_exist(collection_name):
    if collection_name in db.list_collection_names():
        if f'{collection_name}_old' in db.list_collection_names():
            db.drop_collection(f'{collection_name}_old')
        db[collection_name].rename(f'{collection_name}_old')
        return True
    return False

def import_db_collection(collection_name, data):
    data = convert_oid(data)
    return db[collection_name].insert_many(data)


def read_one_row_of_data(username):
    # Iterate through each document in the collection
    for row in data_collection.find():
        # Check if the name does not exist as a key within the "label" object
        if username not in row.get("label", {}):
            return row
    # If no such row is found, return None
    return None


def add_label_to_data(row_id, label, username):
    # Update the document with the provided row_id
    result = data_collection.update_one(
        {"_id": ObjectId(row_id)},
        {"$set": {f"label.{username}": label}}
    )
    # Check if the update was successful
    return result.modified_count == 1


def get_user_performance(username):
    number_of_labels = 0
    total_consensus_degree = 0

    for row in data_collection.find():
        # Retrieve the label dictionary for the current row
        label_dict = row.get("label", {})

        # Check if the user has set a label in this row
        if username in label_dict:
            number_of_labels += 1

            # Calculate the consensus degree for this row
            consensus_count = sum(1 for label in label_dict.values() if label == label_dict[username])
            consensus_degree_in_row = consensus_count / len(label_dict)
            total_consensus_degree += consensus_degree_in_row

    # Avoid division by zero by checking if number_of_labels is greater than zero
    if number_of_labels > 0:
        consensus_degree = total_consensus_degree / number_of_labels
    else:
        consensus_degree = 0

    return number_of_labels, consensus_degree


def get_user_labels(username, page, per_page=10):
    # Skip and limit for pagination
    skip = (page - 1) * per_page
    rows_cursor = data_collection.find({f"label.{username}": {"$exists": True}}).skip(skip).limit(per_page)
    rows = [{"row": row.get('data'), "answer": row.get('label')} for row in rows_cursor]
    total_rows = get_user_performance(username)[0]
    return rows, total_rows


def get_first_conflict_row(data_collection):
    collection = db[data_collection]
    for document in collection.find():
        if 'label_admin' not in document:
            labels = document.get("label", {})
            if labels:
                label_counts = {}
                total_labels = len(labels)
                for user, label in labels.items():
                    label_counts[label] = label_counts.get(label, 0) + 1

                max_label_rate = max(label_counts.values()) / total_labels
                if max_label_rate < 0.5:
                    return document
    return None


def set_admin_label_for_conflicts(row_id, label):
    result = data_collection.update_one(
        {"_id": row_id},
        {"$set": {"label_admin": label}}
    )
    return result.modified_count == 1


def set_admin_label_config(data_collection, labels):
    # Convert the string to a Python list
    array_of_labels = json.loads(labels)
    return ConfigDB.update_data_labels(data_collection, array_of_labels)


def get_user_collection(username):
    user = users_collection.find_one({"username": username})
    if user:
        collection = user.get("collections")
        return collection
    else:
        return None


