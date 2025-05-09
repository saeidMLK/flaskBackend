# from collections import defaultdict
# from pymongo import MongoClient
# from werkzeug.security import generate_password_hash, check_password_hash
# from bson.objectid import ObjectId
# from bson.json_util import dumps
# from flask_login import UserMixin
# from config import ConfigDB
# import json
# from bson import SON, ObjectId
# from werkzeug.exceptions import BadRequest
# import re
#
# client = MongoClient(ConfigDB.MONGODB_URI)
# db = client[ConfigDB.MONGO_DBNAME]
# users_collection = db.users
#
#
# class QuerySecurity:
#     """Silent security validation for MongoDB queries"""
#
#     # Allowed MongoDB query operators (whitelist)
#     ALLOWED_OPERATORS = {
#         '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
#         '$in', '$nin', '$and', '$or', '$not', '$exists'
#     }
#
#     @staticmethod
#     def validate_input(value, field_name, max_length=100):
#         """Universal input validator"""
#         if value is None:
#             raise BadRequest(f"{field_name} cannot be None")
#
#         # ObjectId validation
#         if isinstance(value, ObjectId):
#             return value
#
#         # Basic type validation
#         if isinstance(value, (int, float, bool)):
#             return value
#
#         # String validation
#         if isinstance(value, str):
#             if len(value) > max_length:
#                 raise BadRequest(f"{field_name} exceeds maximum length")
#             if not re.fullmatch(r'^[\w\-.: ]+$', value):
#                 raise BadRequest(f"Invalid characters in {field_name}")
#             return value.strip()
#
#         # Dictionary/operator validation
#         if isinstance(value, dict):
#             return {
#                 k: QuerySecurity._validate_operator(k, v)
#                 for k, v in value.items()
#             }
#
#         raise BadRequest(f"Unsupported type for {field_name}")
#
#     @staticmethod
#     def _validate_operator(operator, value):
#         """Validate MongoDB operators"""
#         if operator.startswith('$'):
#             if operator not in QuerySecurity.ALLOWED_OPERATORS:
#                 raise BadRequest(f"Disallowed operator: {operator}")
#         return QuerySecurity.validate_input(value, "query value")
#
#     @staticmethod
#     def secure_query(base_query):
#         """Convert raw query to safe SON query"""
#         try:
#             return SON(
#                 {k: QuerySecurity.validate_input(v, k)
#                  for k, v in base_query.items()}
#             )
#         except BadRequest:
#             raise  # Re-raise with original context
#         except Exception as e:
#             raise BadRequest("Invalid query parameters")
#
#
#
# # data_collection = db.data
#
# class User(UserMixin):
#     def __init__(self, user_data):
#         self.id = user_data['_id']
#         self.username = user_data['username']
#         self.password_hash = user_data['password_hash']
#         self.role = user_data['role']
#
#     @staticmethod
#     def from_document(doc):
#         if doc:
#             return User(doc)
#         return None
#
#
# def find_user(username):
#     user_data = users_collection.find_one({'username': username})
#     return User.from_document(user_data)
#
#
# def find_user_by_id(user_id):
#     user_data = users_collection.find_one({'_id': ObjectId(user_id)})
#     return User.from_document(user_data)
#
#
# def add_user(username, password, collections, role, creator):
#     if not find_user(username):
#         password_hash = generate_password_hash(password)
#         if role == 'admin':
#             collections = ['all']
#         users_collection.insert_one(
#             {'username': username, 'password_hash': password_hash, 'collections': collections, 'role': role,
#              'creator': [creator]})
#         return True
#     return False
#
#
# def get_all_users():
#     user_docs = users_collection.find()
#     users = [User.from_document(doc) for doc in user_docs]
#     return users
#
#
# def get_supervisor_s_users(username):
#     user_docs = users_collection.find({'creator': username})
#     users = [User.from_document(doc) for doc in user_docs]
#     return users
#
#
# def get_user_role(user_name):
#     user = users_collection.find_one({'username': user_name})
#     return user['role'] if user else None
#
#
# def remove_user_by_name(username):
#     if username != 'admin':
#         query = {'username': username}
#         users_collection.delete_one(query)
#         return True
#     return False
#
#
# def check_password(user, password):
#     return check_password_hash(user.password_hash, password)
#
#
# def get_db_collection_names(sys_collections_included=0):
#     collections = db.list_collection_names()
#     if sys_collections_included:
#         return collections
#     else:
#         collections = db.list_collection_names()
#         items_to_remove = {'users', 'config'}
#         filtered_list = list(set(collections) - items_to_remove)
#         return filtered_list
#
#
# def extract_db_collection(path, collection_name, chunk_size=1000):
#     """
#     Extracts the data from the specified MongoDB collection and writes it to a JSON file in chunks.
#     chunk_size (int): The number of documents to process in each chunk. Default is 1000.
#     """
#     with open(path, 'w', encoding='utf-8') as file:
#         file.write('[')  # Start the JSON array
#         cursor = db[collection_name].find()
#         first = True
#         while True:
#             chunk = []
#             for _ in range(chunk_size):
#                 try:
#                     chunk.append(next(cursor))
#                 except StopIteration:
#                     break
#             if not chunk:
#                 break
#             if not first:
#                 file.write(', ')
#             else:
#                 first = False
#             file.write(dumps(chunk, ensure_ascii=False)[1:-1])  # Remove the surrounding square brackets
#         file.write(']')  # End the JSON array
#
#
# def convert_oid(item):
#     if isinstance(item, dict):
#         for key, value in item.items():
#             if isinstance(value, dict) and '$oid' in value:
#                 item[key] = ObjectId(value['$oid'])
#             else:
#                 convert_oid(value)
#     elif isinstance(item, list):
#         for i in range(len(item)):
#             item[i] = convert_oid(item[i])
#     return item
#
#
# def rename_collection_if_exist(collection_name):
#     if collection_name in db.list_collection_names():
#         if f'{collection_name}_old' in db.list_collection_names():
#             db.drop_collection(f'{collection_name}_old')
#         db[collection_name].rename(f'{collection_name}_old')
#         return True
#     return False
#
#
# def import_db_collection(username, collection_name, data):
#     # Process the data to wrap each row in a "data" key
#     processed_data = [{"data": row} for row in data]
#
#     # Add processed dataset to the collection
#     processed_data = convert_oid(processed_data)  # Convert ObjectId if necessary
#     db[collection_name].insert_many(processed_data)
#
#     # Update the user's collections in the "users" collection
#     db.users.update_one(
#         {'username': username},
#         {'$addToSet': {'collections': collection_name}}
#         # Add the collection name if it's not already present, add collection name in user profile
#     )
#
#     # Set initial configs for new dataset
#     ConfigDB.update_data_labels(collection_name, [])
#     ConfigDB.set_num_labels(collection_name, 0)
#     ConfigDB.set_num_required_labels(collection_name, 1)
#     db['config'].update_one(
#         {'collection': collection_name},  # Match the document
#         {'$set': {'finished_by': []}})
#     return set_data_state(collection_name)
#
#
# def get_user_collection(username):
#     user = users_collection.find_one({"username": username})
#     if user:
#         collection = user.get("collections")
#         return collection
#     else:
#         return None
#
#
# def get_collection_users(collection_name):
#     from bson.son import SON
#     query = SON([("collections", collection_name)])  # Forces literal interpretation
#     db.users.find(query)
#     # Using a direct equality match is safer than allowing operator injection
#     user_docs = db.users.find({'collections': {'$eq': collection_name}})
#     # user_docs = db.users.find({'collections': collection_name})
#     users = [User.from_document(doc) for doc in user_docs]
#     if users:
#         return users
#     else:
#         return None
#
#
# # def read_one_row_of_data(username, collection_name):
# #     # collection_name = get_user_collection(username)
# #     collection = db[collection_name]
# #     # Iterate through each document in the collection
# #     for row in collection.find():
# #         # Check if the name does not exist as a key within the "label" object
# #         if username not in row.get("label", {}):
# #             return row
# #     # If no such row is found, return None
# #     return None
# def read_one_row_of_data(username, collection_name):
#     collection = db[collection_name]
#
#     # Find all documents and annotate with the number of labels
#     rows = collection.find()
#     rows_with_label_count = [
#         (row, len(row.get("label", {}))) for row in rows
#     ]
#
#     # Sort rows by the number of labels in ascending order
#     sorted_rows = sorted(rows_with_label_count, key=lambda x: x[1])
#
#     # Iterate through sorted rows to find the one not labeled by the user
#     for row, label_count in sorted_rows:
#         if username not in row.get("label", {}):
#             return row
#
#     # If no such row is found it means user finished labeling for this and increase num_labels
#     # , return None
#     collection = db['config'].find_one({'collection': collection_name})
#     num_labels = collection['num_labels'] + 1
#
#     # Check if the field exists
#     if 'finished_by' in collection:
#         # Check if the value already exists in the field
#         if username not in collection['finished_by']:
#             # Add the new value to the field
#             db['config'].update_one(
#                 {'collection': collection_name},  # Match the document
#                 {'$push': {'finished_by': username}, '$set': {'num_labels': num_labels}}
#             )
#     else:
#         # Add the new field with the value
#         db['config'].update_one(
#             {'collection': collection_name},  # Match the document
#             {'$set': {'finished_by': username, 'num_labels': num_labels}}
#         )
#     set_data_state(collection_name)
#     return None
#
#
# def add_label_to_data(row_id, label, username, collection_name):
#     # collection_name = get_user_collection(username)
#     collection = db[collection_name]
#     # Update the document with the provided row_id
#     result = collection.update_one(
#         {"_id": ObjectId(row_id)},
#         {"$set": {f"label.{username}": label}}
#     )
#     # Check if the update was successful
#     return result.modified_count == 1
#
#
# def get_user_performance(username, collection_name):
#     number_of_labels = 0
#     total_consensus_degree = 0
#     # collection_name = get_user_collection(username)
#     collection = db[collection_name]
#     total_rows = collection.count_documents({})  # Get the total number of rows in the collection
#
#     for row in collection.find():
#         # Retrieve the label dictionary for the current row
#         label_dict = row.get("label", {})
#
#         # Check if the user has set a label in this row
#         if username in label_dict:
#             number_of_labels += 1
#
#             # Calculate the consensus degree for this row
#             consensus_count = sum(1 for label in label_dict.values() if label == label_dict[username])
#             consensus_degree_in_row = consensus_count / len(label_dict)
#             total_consensus_degree += consensus_degree_in_row
#
#     # Avoid division by zero by checking if number_of_labels is greater than zero
#     if number_of_labels > 0:
#         consensus_degree = round((total_consensus_degree / number_of_labels) * 100)
#         label_percentage = round(
#             (number_of_labels / total_rows) * 100)  # Calculate the percentage of labels set by the user
#     else:
#         consensus_degree = 0
#         label_percentage = 0
#
#     return number_of_labels, consensus_degree, label_percentage
#
#
# def get_user_labels(username, collection_name, page, per_page=10):
#     # collection_name = get_user_collection(username)
#     collection = db[collection_name]
#     # Skip and limit for pagination
#     skip = (page - 1) * per_page
#     rows_cursor = collection.find({f"label.{username}": {"$exists": True}}).skip(skip).limit(per_page)
#     rows = [{"row": row.get('data'), "answer": row.get('label')} for row in rows_cursor]
#     total_rows = get_user_performance(username, collection_name)[0]
#     return rows, total_rows
#
#
# def get_first_conflict_row(collection_name, threshold):
#     collection = db[collection_name]
#     for document in collection.find():
#         if 'label_admin' not in document:
#             labels = document.get("label", {})
#             if labels:
#                 label_counts = {}
#                 total_labels = len(labels)
#                 for user, label in labels.items():
#                     label_counts[label] = label_counts.get(label, 0) + 1
#
#                 max_label_rate = max(label_counts.values()) / total_labels
#                 if max_label_rate < threshold:
#                     return document
#     return None
#
#
# def set_admin_label_for_conflicts(collection_name, row_id, label):
#     collection = db[collection_name]
#     result = collection.update_one(
#         {"_id": row_id},
#         {"$set": {"label_admin": label}}
#     )
#     return result.modified_count == 1
#
#
# def remove_conflicted_row(collection_name, row_id):
#     collection = db[collection_name]
#     result = collection.delete_one({"_id": row_id})
#     return result.deleted_count == 1
#
#
# def set_data_configs(data_collection, labels, num_required_labels):
#     # Convert the string to a Python list
#     array_of_labels = json.loads(labels)
#     ConfigDB.update_data_labels(data_collection, array_of_labels)
#     return ConfigDB.set_num_required_labels(data_collection, num_required_labels)
#
#
# def calculate_and_set_average_label(collection_name):
#     try:
#         collection = db[collection_name]
#         for document in collection.find():
#             if 'label_admin' in document:
#                 average_label = document['label_admin']
#             else:
#                 labels = document.get("label", {})
#                 value_count = {}
#                 for value in labels.values():
#                     if value in value_count:
#                         value_count[value] += 1
#                     else:
#                         value_count[value] = 1
#                 if value_count:
#                     average_label = max(value_count, key=value_count.get)
#                 else:
#                     average_label = None  # Or set a default value if no labels are found
#             # Update the document with the calculated average_label
#             collection.update_one(
#                 {"_id": document["_id"]},
#                 {"$set": {"average_label": average_label}}
#             )
#         return True
#     except Exception:
#         return False
#
#
# def get_recent_labels(username, collection_name, limit=10):
#     # collections = get_user_collection(username)
#     collection = db[collection_name]
#     rows = collection.find({f"label.{username}": {"$exists": True}}, {'data': 1, 'label': 1}).sort('_id', -1).limit(
#         limit)
#     recent_labels = []
#     for row in rows:
#         recent_labels.append({'id': str(row['_id']), 'data': row.get('data', ''), 'labels': row.get('label', {})})
#     return recent_labels
#
#
# def update_label(row_id, username, new_label_value, collection_name):
#     # collection_name = get_user_collection(username)
#     collection = db[collection_name]
#     result = collection.update_one(
#         {'_id': ObjectId(row_id)},
#         {'$set': {f'label.{username}': new_label_value}}
#     )
#     return result.modified_count > 0
#
#
# def get_label_options(collection_name):
#     return ConfigDB.get_data_labels(collection_name)
#
#
# def set_data_state(collection_name):
#     collection = db['config'].find_one({'collection': collection_name})
#     num_required_labels = collection['num_required_labels']
#     num_labels = collection['num_labels']
#     if num_labels < 1 or num_labels == None:
#         state = 'unlabeled'
#     elif num_labels < num_required_labels:
#         state = 'labeling'
#     else:
#         state = 'labeled'
#     db['config'].update_one({'collection': collection_name}, {'$set': {'state': state}})
#     return state
#
#
# def get_data_states(user):
#     if user == 'admin':
#         collections = get_db_collection_names(0)
#     else:
#         collections = get_user_collection(user)
#
#     data_and_states = defaultdict(list)
#     for collection in collections:
#         collection_row = db['config'].find_one({"collection": collection})
#         state = collection_row['state']
#         data_and_states[state].append(collection)
#     return data_and_states
#
#
# def get_top_users():
#     collections = get_db_collection_names(0)
#     if collections is None:
#         collections = []
#     users = get_all_users()
#     categorized_users = defaultdict(list)
#
#     for user in users:
#         categorized_users[user.role].append(user.username)
#
#     user_data = defaultdict(
#         lambda: {'total_labels': 0, 'total_consensus': 0, 'collections_count': 0,
#                  'collection_names': []})  # To store data for each user
#
#     if categorized_users['user']:
#         for collection in collections:
#             # check if collection have been labeled completely.
#             if collection in get_data_states('admin')['labeled']:
#                 for user in categorized_users['user']:
#                     if user in db['config'].find_one({'collection': collection})['finished_by']:
#                         user_performance = get_user_performance(user, collection)
#                         # Check if user_performance is valid before proceeding
#                         if user_performance:
#                             number_of_labels = user_performance[0]
#                             consensus_degree = user_performance[1]
#                             # Add user data (username, number_of_labels, consensus_degree)
#                             # Update total labels and consensus for this user
#                             user_data[user]['total_labels'] += number_of_labels
#                             user_data[user]['total_consensus'] += consensus_degree
#                             user_data[user]['collections_count'] += 1
#                             user_data[user]['collection_names'].append(collection)
#                         else:
#                             continue
#                     else:
#                         continue
#             else:
#                 continue
#
#         # Now calculate the F-score based on total_labels and average_consensus for each user
#     ranked_users = []
#     for user, data in user_data.items():
#         total_labels = data['total_labels']
#         collections_count = data['collections_count']
#
#         # Calculate the average consensus degree
#         if collections_count > 0:
#             avg_consensus = data['total_consensus'] / collections_count
#         else:
#             avg_consensus = 0
#
#         # Calculate F-score using total_labels and avg_consensus
#         if total_labels + avg_consensus > 0:
#             f_score = 2 * (total_labels * avg_consensus) / (total_labels + avg_consensus)
#         else:
#             f_score = 0
#
#         score = int(total_labels * (avg_consensus / 100))
#         collections = data['collection_names']
#         ranked_users.append({
#             'username': user,
#             'total_labels': total_labels,
#             'avg_consensus': avg_consensus,
#             'f_score': f_score,
#             'score': score,
#             'collections': collections
#         })
#
#     # Sort users based on F-score in descending order
#     ranked_users = sorted(ranked_users, key=lambda x: x['score'], reverse=True)
#     return ranked_users
#
#
# def insert_data_into_collection(collection_name, data):
#     try:
#         # Process the data to wrap each row in a "data" key
#         processed_data = [{"data": row} for row in data]
#         result = db[collection_name].insert_many(processed_data)
#         return result.inserted_ids
#     except Exception as e:
#         raise Exception(f"Error inserting data into collection {collection_name}: {str(e)}")
#
#
# def assign_collection_to_user(username, collection_name):
#     # Get the user's current document to check the type of 'collections'
#     user_data = db.users.find_one({'username': username})
#
#     if user_data:
#         # Check if 'collections' is a string and convert it to an array
#         if isinstance(user_data.get('collections'), str):
#             db.users.update_one(
#                 {'username': username},
#                 {'$set': {'collections': [user_data['collections']]}}  # Convert string to array
#             )
#
#     # Update the user's collections in the "users" collection
#     db.users.update_one(
#         {'username': username},
#         {'$addToSet': {'collections': collection_name}}  # Add the collection name if it's not already present
#     )
#
#
# def remove_data_collection(collection_name):
#     try:
#         db[collection_name].drop()
#         config_collection = db['config']
#         config_collection.delete_one({'collection': collection_name})
#         users_collection.update_many(
#             {'collections': collection_name},
#             {'$pull': {'collections': collection_name}})
#         return True
#     except Exception:
#         return False
#
#
# def get_assigned_label_db_collection_names(username):
#     if username == 'admin':
#         collections = db.list_collection_names()
#         items_to_remove = {'users', 'config'}
#         collections = list(set(collections) - items_to_remove)
#         filtered_list = []
#         for collection in collections:
#             config = db.config.find_one({'collection': collection})
#             # print(config)
#             if not config['labels']:
#                 continue
#             filtered_list.append(collection)
#         return filtered_list
#     else:
#         user = users_collection.find_one({"username": username})
#         collections = user.get("collections")
#         user_filtered_list = []
#         for collection in collections:
#             config = db.config.find_one({'collection': collection})
#             # print(config)
#             if not config['labels']:
#                 continue
#             user_filtered_list.append(collection)
#         return user_filtered_list
#
#
# def revoke_collection_from_user(username, collection):
#     users_collection.update_one(
#         {"username": username},
#         {'$pull': {"collections": collection}} )
#
#
# def get_unassigned_label_db_collection_names(username):
#     if username == 'admin':
#         collections = db.list_collection_names()
#         items_to_remove = {'users', 'config'}
#         collections = list(set(collections) - items_to_remove)
#         filtered_list = []
#         for collection in collections:
#             config = db.config.find_one({'collection': collection})
#             # print(config)
#             if config['labels']:
#                 continue
#             filtered_list.append(collection)
#         return filtered_list
#     else:
#         user = users_collection.find_one({"username": username})
#         collections = user.get("collections")
#         user_filtered_list = []
#         for collection in collections:
#             config = db.config.find_one({'collection': collection})
#             # print(config)
#             if config['labels']:
#                 continue
#             user_filtered_list.append(collection)
#         return user_filtered_list
#
#
# def change_password(username, password):
#     new_password_hash = generate_password_hash(password)
#     result = users_collection.update_one(
#         {'username': username},
#         {'$set': {'password_hash': new_password_hash}}
#     )
#     # Check if the user was found and updated
#     if result.modified_count == 1:
#         return True
#     else:
#         return False
