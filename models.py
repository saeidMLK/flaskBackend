from collections import defaultdict

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
# data_collection = db.data

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
        users_collection.insert_one({'username': username, 'password_hash': password_hash, 'collections': collections, 'role': role})
        return True
    return False


def get_all_users():
    user_docs = users_collection.find()
    users = [User.from_document(doc) for doc in user_docs]
    return users


def get_user_role(user_name):
    user = users_collection.find_one({'username': user_name})
    return user['role'] if user else None


def remove_user_by_name(username):
    if username != 'admin':
        query = {'username': username}
        users_collection.delete_one(query)
        return True
    return False


def check_password(user, password):
    return check_password_hash(user.password_hash, password)


def get_db_collection_names(sys_collections_included=0):
    collections = db.list_collection_names()
    if sys_collections_included:
        return collections
    else:
        collections = db.list_collection_names()
        items_to_remove = {'users', 'config'}
        filtered_list = list(set(collections) - items_to_remove)
        return filtered_list

def extract_db_collection(path, collection_name, chunk_size=1000):
    """
    Extracts the data from the specified MongoDB collection and writes it to a JSON file in chunks.
    chunk_size (int): The number of documents to process in each chunk. Default is 1000.
    """
    with open(path, 'w',  encoding='utf-8') as file:
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
            file.write(dumps(chunk, ensure_ascii=False)[1:-1])  # Remove the surrounding square brackets
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


def get_user_collection(username):
    user = users_collection.find_one({"username": username})
    if user:
        collection = user.get("collections")
        return collection
    else:
        return None


def get_collection_users(collection_name):
    user_docs = db.users.find({'collections': collection_name})
    users = [User.from_document(doc) for doc in user_docs]
    if users:
        return users
    else:
        return None


def read_one_row_of_data(username, collection_name):
    # collection_name = get_user_collection(username)
    collection = db[collection_name]
    # Iterate through each document in the collection
    for row in collection.find():
        # Check if the name does not exist as a key within the "label" object
        if username not in row.get("label", {}):
            return row
    # If no such row is found, return None
    return None


def add_label_to_data(row_id, label, username, collection_name):
    # collection_name = get_user_collection(username)
    collection = db[collection_name]
    # Update the document with the provided row_id
    result = collection.update_one(
        {"_id": ObjectId(row_id)},
        {"$set": {f"label.{username}": label}}
    )
    # Check if the update was successful
    return result.modified_count == 1


def get_user_performance(username, collection_name):
    number_of_labels = 0
    total_consensus_degree = 0
    # collection_name = get_user_collection(username)
    collection = db[collection_name]
    total_rows = collection.count_documents({})  # Get the total number of rows in the collection
    for row in collection.find():
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
        consensus_degree = round((total_consensus_degree / number_of_labels) *100)
        label_percentage = round((number_of_labels / total_rows) * 100)  # Calculate the percentage of labels set by the user
    else:
        consensus_degree = 0
        label_percentage = 0

    return number_of_labels, consensus_degree, label_percentage


def get_user_labels(username, collection_name, page, per_page=10):
    # collection_name = get_user_collection(username)
    collection = db[collection_name]
    # Skip and limit for pagination
    skip = (page - 1) * per_page
    rows_cursor = collection.find({f"label.{username}": {"$exists": True}}).skip(skip).limit(per_page)
    rows = [{"row": row.get('data'), "answer": row.get('label')} for row in rows_cursor]
    total_rows = get_user_performance(username, collection_name)[0]
    return rows, total_rows


def get_first_conflict_row(collection_name, threshold):
    collection = db[collection_name]
    for document in collection.find():
        if 'label_admin' not in document:
            labels = document.get("label", {})
            if labels:
                label_counts = {}
                total_labels = len(labels)
                for user, label in labels.items():
                    label_counts[label] = label_counts.get(label, 0) + 1

                max_label_rate = max(label_counts.values()) / total_labels
                if max_label_rate < threshold:
                    return document
    return None


def set_admin_label_for_conflicts(collection_name, row_id, label):
    collection = db[collection_name]
    result = collection.update_one(
        {"_id": row_id},
        {"$set": {"label_admin": label}}
    )
    return result.modified_count == 1


def set_data_configs(data_collection, labels, num_required_labels):
    # Convert the string to a Python list
    array_of_labels = json.loads(labels)
    ConfigDB.update_data_labels(data_collection, array_of_labels)
    return ConfigDB.set_num_required_labels(data_collection, num_required_labels)



def calculate_and_set_average_label(collection_name):
    try:
        collection = db[collection_name]
        for document in collection.find():
            if 'label_admin' in document:
                average_label = document['label_admin']
            else:
                labels = document.get("label", {})
                value_count = {}
                for value in labels.values():
                    if value in value_count:
                        value_count[value] += 1
                    else:
                        value_count[value] = 1
                if value_count:
                    average_label = max(value_count, key=value_count.get)
                else:
                    average_label = None  # Or set a default value if no labels are found
            # Update the document with the calculated average_label
            collection.update_one(
                {"_id": document["_id"]},
                {"$set": {"average_label": average_label}}
            )
        return True
    except Exception:
        return False

# calculate_and_set_average_label("data_old")


def get_recent_labels(username, collection_name, limit=10):
    # collections = get_user_collection(username)
    collection = db[collection_name]
    rows = collection.find({f"label.{username}": {"$exists": True}}, {'data': 1, 'label': 1}).sort('_id', -1).limit(limit)
    recent_labels = []
    for row in rows:
        recent_labels.append({'id': str(row['_id']), 'data': row.get('data', ''), 'labels': row.get('label', {})})
    return recent_labels


def update_label(row_id, username, new_label_value, collection_name):
    # collection_name = get_user_collection(username)
    collection = db[collection_name]
    result = collection.update_one(
        {'_id': ObjectId(row_id)},
        {'$set': {f'label.{username}': new_label_value}}
    )
    return result.modified_count > 0


def get_label_options(collection_name):
    return ConfigDB.get_data_labels(collection_name)


def get_top_users(k=3):
    collections = get_db_collection_names(0)
    if collections is None:
        collections = []
    users = get_all_users()
    categorized_users = defaultdict(list)

    for user in users:
        categorized_users[user.role].append(user.username)

    user_data = defaultdict(lambda: {'total_labels': 0, 'total_consensus': 0, 'collections_count': 0})  # To store data for each user

    if categorized_users['user']:
        for collection in collections:
            for user in categorized_users['user']:
                user_performance = get_user_performance(user, collection)
                # Check if user_performance is valid before proceeding
                if user_performance:
                    number_of_labels = user_performance[0]
                    consensus_degree = user_performance[1]
                    # Add user data (username, number_of_labels, consensus_degree)
                    # Update total labels and consensus for this user
                    user_data[user]['total_labels'] += number_of_labels
                    user_data[user]['total_consensus'] += consensus_degree
                    user_data[user]['collections_count'] += 1
                else:
                    continue

        # Now calculate the F-score based on total_labels and average_consensus for each user
    ranked_users = []

    for user, data in user_data.items():
        total_labels = data['total_labels']
        collections_count = data['collections_count']

        # Calculate the average consensus degree
        if collections_count > 0:
            avg_consensus = data['total_consensus'] / collections_count
        else:
            avg_consensus = 0

        # Calculate F-score using total_labels and avg_consensus
        if total_labels + avg_consensus > 0:
            f_score = 2 * (total_labels * avg_consensus) / (total_labels + avg_consensus)
        else:
            f_score = 0

        ranked_users.append({
            'username': user,
            'total_labels': total_labels,
            'avg_consensus': avg_consensus,
            'f_score': f_score
        })

    # Sort users based on F-score in descending order
    ranked_users = sorted(ranked_users, key=lambda x: x['f_score'], reverse=True)

    if len(categorized_users['user']) < k:
        return ranked_users[:len(categorized_users['user'])]
    else:
        return ranked_users[:k]


def set_data_state(collection_name):
    collection = db['config'].find_one({'collection': collection_name})
    num_required_labels = collection['num_required_labels']
    print(num_required_labels)
    num_labels = collection['num_labels']
    print(num_labels)
    if num_labels < 1 or num_labels == None:
        state = 'unlabeled'
    elif num_labels < num_required_labels:
        state = 'labeling'
    else:
        state = 'labeled'
    db['config'].update_one({'collection': collection_name}, {'$set': {'state': state}})
    return state


def get_data_states():
    collections = get_db_collection_names(0)
    data_and_states = defaultdict(list)
    for collection in collections:
        collection_row = db['config'].find_one({"collection": collection})
        state = collection_row['state']
        data_and_states[state].append(collection)
    return data_and_states
