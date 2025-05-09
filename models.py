from collections import defaultdict
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.json_util import dumps
from flask_login import UserMixin
from config import ConfigDB
import json
from bson import SON, ObjectId
from werkzeug.exceptions import BadRequest
import re
import os

client = MongoClient(ConfigDB.MONGODB_URI)
db = client[ConfigDB.MONGO_DBNAME]
users_collection = db.users


class QuerySecurity:
    """Silent security validation for MongoDB queries"""

    # Allowed MongoDB query operators (whitelist)
    ALLOWED_OPERATORS = {
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
        '$in', '$nin', '$and', '$or', '$not', '$exists'
    }

    @staticmethod
    def validate_input(value, field_name, max_length=200):
        """Universal input validator"""
        if value is None:
            raise BadRequest(f"{field_name} cannot be None")

        # ObjectId validation
        if isinstance(value, ObjectId):
            return value

        # Basic type validation
        if isinstance(value, (int, float, bool)):
            return value

        # String validation
        if isinstance(value, str):
            if len(value) > max_length:
                raise BadRequest(f"{field_name} exceeds maximum length")
            if not re.fullmatch(r'^[\w\-.: ]+$', value):
                raise BadRequest(f"Invalid characters in {field_name}")
            return value.strip()

        # Dictionary/operator validation
        if isinstance(value, dict):
            return {
                k: QuerySecurity._validate_operator(k, v)
                for k, v in value.items()
            }

        raise BadRequest(f"Unsupported type for {field_name}")

    @staticmethod
    def _validate_operator(operator, value):
        """Validate MongoDB operators"""
        if operator.startswith('$'):
            if operator not in QuerySecurity.ALLOWED_OPERATORS:
                raise BadRequest(f"Disallowed operator: {operator}")
        return QuerySecurity.validate_input(value, "query value")

    @staticmethod
    def secure_query(base_query):
        """Convert raw query to safe SON query"""
        try:
            return SON(
                {k: QuerySecurity.validate_input(v, k)
                 for k, v in base_query.items()}
            )
        except BadRequest:
            raise  # Re-raise with original context
        except Exception as e:
            raise BadRequest("Invalid query parameters")


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

#safe
def find_user(username):
    # Validate username input
    safe_username = QuerySecurity.validate_input(
        username,
        "username")

    # Build secure query
    query = QuerySecurity.secure_query({'username': {'$eq': safe_username}})

    # Execute query
    user_data = users_collection.find_one(query)

    return User.from_document(user_data) if user_data else None


def find_user_by_id(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User.from_document(user_data)

#safe
def add_user(username, password, collections, role, creator):
    # Validate all inputs
    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    if not isinstance(password, str):# or len(password) < 8:
        raise BadRequest("Password must be a string with at least 8 characters")

    # Validate role
    if role not in {'admin', 'user', 'reviewer'}:  # Adjust roles as needed
        raise BadRequest("Invalid user role")

    # Validate collections
    if not isinstance(collections, list):
        raise BadRequest("Collections must be a list")
    safe_collections = [QuerySecurity.validate_input(c, "collection") for c in collections]

    # Validate creator
    safe_creator = QuerySecurity.validate_input(creator, "creator", max_length=50)

    # Check for existing user (secure query)
    if users_collection.find_one(
            QuerySecurity.secure_query({'username': {'$eq': safe_username}})
    ):
        return False

    # Handle admin case
    if role == 'admin':
        safe_collections = ['all']

    # Secure password hashing
    password_hash = generate_password_hash(password)

    # Insert operation - password_hash excluded from validation
    users_collection.insert_one({
        'username': safe_username,
        'password_hash': password_hash,  # Not validated
        'collections': safe_collections,
        'role': role,
        'creator': [safe_creator]
    })
    return True


def get_all_users():
    user_docs = users_collection.find()
    users = [User.from_document(doc) for doc in user_docs]
    return users


def get_supervisor_s_users(username):
    user_docs = users_collection.find({'creator': username})
    users = [User.from_document(doc) for doc in user_docs]
    return users


# def get_user_role(user_name):
#     user = users_collection.find_one({'username': user_name})
#     return user['role'] if user else None

#safe
def remove_user_by_name(username):
    # Validate input using QuerySecurity
    safe_username = QuerySecurity.validate_input(username, "username")

    # Maintain original admin protection
    if safe_username != 'admin':
        # Use secure query
        query = QuerySecurity.secure_query({'username': safe_username})
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

#safe
def extract_db_collection(path, collection_name, chunk_size=10000):
    # Validate inputs
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name", max_length=64)
    safe_chunk_size = max(1, min(int(chunk_size), 10001))  # Keep between 1-10,000

    try:
        with open(path, 'w', encoding='utf-8') as file:
            file.write('[')  # Start JSON array

            # Get cursor with no timeout
            cursor = db[safe_collection].find(no_cursor_timeout=True)
            first_chunk = True

            try:
                while True:
                    chunk = []
                    for _ in range(safe_chunk_size):
                        try:
                            doc = next(cursor)
                            chunk.append(doc)
                        except StopIteration:
                            break

                    if not chunk:
                        break

                    if not first_chunk:
                        file.write(', ')
                    else:
                        first_chunk = False

                    # Write chunk without surrounding brackets
                    json_chunk = dumps(chunk, ensure_ascii=False)[1:-1]
                    file.write(json_chunk)

            finally:
                cursor.close()  # Ensure cursor is always closed

            file.write(']')  # End JSON array

    except Exception as e:
        if os.path.exists(path):
            os.remove(path)  # Clean up partial file
        raise BadRequest(f"Export failed: {str(e)}")

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


# def rename_collection_if_exist(collection_name):
#     if collection_name in db.list_collection_names():
#         if f'{collection_name}_old' in db.list_collection_names():
#             db.drop_collection(f'{collection_name}_old')
#         db[collection_name].rename(f'{collection_name}_old')
#         return True
#     return False

#safe
def import_db_collection(username, collection_name, data):
    # Validate all string inputs
    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name", max_length=64)

    # Validate data structure
    if not isinstance(data, list) or len(data) == 0:
        raise BadRequest("Data must be a non-empty list")

    processed_data = []
    for row in data:
        # Basic type check
        if not isinstance(row, dict):
            raise BadRequest("Each row must be a dictionary")

        # Optional: validate specific dangerous fields
        if "_id" in row:
            QuerySecurity.validate_input(row["_id"], "row _id")

        processed_data.append({"data": row})  # Keep original data intact

    # Secure database operations
    try:
        # Insert processed data
        processed_data = convert_oid(processed_data)
        db[safe_collection].insert_many(processed_data)
        # Update user's collections
        db.users.update_one(
            QuerySecurity.secure_query({'username': safe_username}),
            QuerySecurity.secure_query({
                '$addToSet': {'collections': safe_collection}
            })
        )
        # Set initial configs
        ConfigDB.update_data_labels(safe_collection, [])
        ConfigDB.set_num_labels(safe_collection, 0)
        ConfigDB.set_num_required_labels(safe_collection, 1)
        db['config'].update_one(
            QuerySecurity.secure_query({'collection': safe_collection}),
           {'$set': {'finished_by': []}})
        return set_data_state(safe_collection)

    except Exception as e:
        # Rollback if any operation fails?
        raise BadRequest(f"Database operation failed: {str(e)}")

#safe
def get_user_collection(username):
    """Get user's collection with security validation"""
    try:
        # Validate username input
        safe_username = QuerySecurity.validate_input(
            username,
            "username",
            max_length=50  # Adjust max length as needed
        )

        # Build secure query
        query = QuerySecurity.secure_query({
            "username": {"$eq": safe_username}
        })

        # Execute query
        user = users_collection.find_one(query)

        # Safely access nested field
        if user and isinstance(user.get("collections"), (str, list, dict)):
            return user["collections"]
        return None

    except BadRequest as e:
        # Re-raise with original error message
        raise
    except Exception as e:
        # Generic error handling (optional)
        raise ValueError("Failed to retrieve user collection") from e

#safe
def get_collection_users(collection_name):
    """Get all users belonging to a specific collection with full security validation"""
    try:
        # 1. Strict input validation
        safe_collection = QuerySecurity.validate_input(
            collection_name,
            "collection_name",
            max_length=100  # Adjust based on your needs
        )

        # 2. Build parameterized query
        query = QuerySecurity.secure_query({
            'collections': {
                '$eq': safe_collection  # Explicit equality match
                # Alternative for array fields: '$in' if collections is an array
            }
        })

        # 3. Execute secured query
        user_docs = db.users.find(query)

        # 4. Safe document processing
        users = []
        for doc in user_docs:
            if isinstance(doc, dict):  # Verify document type
                try:
                    user = User.from_document(doc)
                    if user:  # Verify valid user object
                        users.append(user)
                except (AttributeError, ValueError) as e:
                    continue  # Skip invalid user documents

        return users if users else None

    except BadRequest:
        raise  # Re-raise validation errors
    except Exception as e:
        # Consider custom exception class for DB errors
        raise RuntimeError("Failed to retrieve collection users") from e

#safe
def read_one_row_of_data(username, collection_name):
    """Get next unlabeled row for user with security but same functionality"""
    try:
        # Validate inputs (silent version without logging)
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Invalid username")
        if not isinstance(collection_name, str) or not collection_name.strip():
            raise ValueError("Invalid collection name")

        safe_username = username.strip()
        safe_collection = collection_name.strip()

        # Get collection - same as original
        collection = db[safe_collection]

        # Find all documents - maintaining original functionality
        rows = collection.find({})
        rows_with_label_count = [
            (row, len(row.get("label", {}))) for row in rows
            if isinstance(row, dict) and isinstance(row.get("label", {}), dict)
        ]

        # Sort exactly as before
        sorted_rows = sorted(rows_with_label_count, key=lambda x: x[1])

        # Find first unlabeled row - preserving original logic
        for row, _ in sorted_rows:
            if isinstance(row, dict) and safe_username not in row.get("label", {}):
                # Ensure the row has all expected fields
                if not all(key in row for key in ['data', '_id']):
                    continue
                return row

        # Config update - same logic but with basic validation
        config_data = db['config'].find_one({'collection': safe_collection})
        if config_data:
            num_labels = config_data.get('num_labels', 0) + 1
            update_op = {
                '$inc': {'num_labels': 1},
                '$addToSet': {'finished_by': safe_username}
            }
        else:
            num_labels = 1
            update_op = {
                '$set': {
                    'collection': safe_collection,
                    'num_labels': num_labels,
                    'finished_by': [safe_username]
                }
            }

        db['config'].update_one(
            {'collection': safe_collection},
            update_op,
            upsert=True
        )

        set_data_state(safe_collection)
        return None

    except Exception as e:
        # Preserve original error handling
        raise ValueError(f"Error accessing data: {str(e)}")

#safe
def add_label_to_data(row_id, label, username, collection_name):
    try:
        safe_row_id = ObjectId(row_id)  # Will raise exception if invalid
    except:
        raise BadRequest("Invalid document ID format")

    safe_label = QuerySecurity.validate_input(label, "label", max_length=400)
    safe_username = QuerySecurity.validate_input(username, "username")
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name")

    # Build secure query
    collection = db[safe_collection]
    query = QuerySecurity.secure_query({"_id": safe_row_id})
    update = QuerySecurity.secure_query({
        "$set": {f"label.{safe_username}": safe_label}
    })

    # Execute update
    result = collection.update_one(query, update)
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
        consensus_degree = round((total_consensus_degree / number_of_labels) * 100)
        label_percentage = round(
            (number_of_labels / total_rows) * 100)  # Calculate the percentage of labels set by the user
    else:
        consensus_degree = 0
        label_percentage = 0

    return number_of_labels, consensus_degree, label_percentage


def get_user_labels(username, collection_name, page, per_page=10):
    safe_username = QuerySecurity.validate_input(username, "username")
    collection = db[collection_name]
    # Skip and limit for pagination
    skip = (page - 1) * per_page
    rows_cursor = collection.find({f"label.{safe_username}": {"$exists": True}}).skip(skip).limit(per_page)
    rows = [{"row": row.get('data'), "answer": row.get('label')} for row in rows_cursor]
    total_rows = get_user_performance(safe_username, collection_name)[0]
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


#safe
def set_admin_label_for_conflicts(collection_name, row_id, label):
    # Validate all inputs using QuerySecurity
    safe_collection = QuerySecurity.validate_input(
        collection_name,
        "collection_name")
    safe_row_id = QuerySecurity.validate_input(row_id, "row_id")
    safe_label = QuerySecurity.validate_input(label, "label", max_length=500)  # Adjust max length as needed

    # Build secure query
    collection = db[safe_collection]
    query = QuerySecurity.secure_query({"_id": safe_row_id})
    update = QuerySecurity.secure_query({"$set": {"label_admin": safe_label}})

    # Execute with original behavior
    result = collection.update_one(query, update)
    return result.modified_count == 1

#safe
def remove_conflicted_row(collection_name, row_id):
    # Validate inputs using QuerySecurity
    safe_collection = QuerySecurity.validate_input(
        collection_name,
        "collection_name")
    safe_row_id = QuerySecurity.validate_input(row_id, "row_id")

    # Build secure query
    collection = db[safe_collection]
    query = QuerySecurity.secure_query({"_id": safe_row_id})

    # Execute with original behavior
    result = collection.delete_one(query)
    return result.deleted_count == 1


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


def get_recent_labels(username, collection_name, limit=10):
    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    collection = db[collection_name]
    rows = collection.find({f"label.{safe_username}": {"$exists": True}}, {'data': 1, 'label': 1}).sort('_id', -1).limit(
        limit)
    recent_labels = []
    for row in rows:
        recent_labels.append({'id': str(row['_id']), 'data': row.get('data', ''), 'labels': row.get('label', {})})
    return recent_labels


#safe
def update_label(row_id, username, new_label_value, collection_name):
    # Validate all inputs
    try:
        safe_row_id = ObjectId(row_id)  # Validates if it's a proper ObjectId
    except:
        raise BadRequest("Invalid document ID format")

    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name", max_length=100)

    # Validate label value (adjust according to your expected label format)
    if not isinstance(new_label_value, (str, int, float, bool)):
        raise BadRequest("Label value must be a string, number, or boolean")

    # Secure field name construction
    label_field = f"label.{safe_username}"
    if not re.match(r'^label\.[a-zA-Z0-9_-]+$', label_field):
        raise BadRequest("Invalid label field format")

    # Secure update operation
    collection = db[safe_collection]
    result = collection.update_one(
        QuerySecurity.secure_query({'_id': {'$eq': safe_row_id}}),
        QuerySecurity.secure_query({'$set': {label_field: new_label_value}})
    )

    return result.modified_count > 0


def get_label_options(collection_name):
    return ConfigDB.get_data_labels(collection_name)


#safe
def set_data_state(collection_name):
    # Validate input first
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name")

    # Secure query for finding config
    config = db['config'].find_one(
        QuerySecurity.secure_query({'collection': {'$eq': safe_collection}})
    )

    if not config:
        raise ValueError(f"Configuration not found for collection: {safe_collection}")

    # Validate and extract numeric values
    try:
        num_required_labels = int(config.get('num_required_labels', 0))
        num_labels = int(config.get('num_labels', 0))
    except (TypeError, ValueError):
        raise ValueError("Invalid numeric values in configuration")

    # Determine state with additional validation
    if num_labels < 0 or num_required_labels < 0:
        raise ValueError("Label counts cannot be negative")

    if num_labels < 1:
        state = 'unlabeled'
    elif num_labels < num_required_labels:
        state = 'labeling'
    else:
        state = 'labeled'

    # Secure update operation
    db['config'].update_one(
        QuerySecurity.secure_query({'collection': {'$eq': safe_collection}}),
        QuerySecurity.secure_query({'$set': {'state': state}})
    )

    return state


def get_data_states(user):
    safe_username = QuerySecurity.validate_input(user, "username", max_length=50)
    if safe_username == 'admin':
        collections = get_db_collection_names(0)
    else:
        collections = get_user_collection(safe_username)

    data_and_states = defaultdict(list)
    for collection in collections:
        collection_row = db['config'].find_one({"collection": collection})
        state = collection_row['state']
        data_and_states[state].append(collection)
    return data_and_states


def get_top_users():
    collections = get_db_collection_names(0)
    if collections is None:
        collections = []
    users = get_all_users()
    categorized_users = defaultdict(list)

    for user in users:
        categorized_users[user.role].append(user.username)

    user_data = defaultdict(
        lambda: {'total_labels': 0, 'total_consensus': 0, 'collections_count': 0,
                 'collection_names': []})  # To store data for each user

    if categorized_users['user']:
        for collection in collections:
            # check if collection have been labeled completely.
            if collection in get_data_states('admin')['labeled']:
                for user in categorized_users['user']:
                    if user in db['config'].find_one({'collection': collection})['finished_by']:
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
                            user_data[user]['collection_names'].append(collection)
                        else:
                            continue
                    else:
                        continue
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

        score = int(total_labels * (avg_consensus / 100))
        collections = data['collection_names']
        ranked_users.append({
            'username': user,
            'total_labels': total_labels,
            'avg_consensus': avg_consensus,
            'f_score': f_score,
            'score': score,
            'collections': collections
        })

    # Sort users based on F-score in descending order
    ranked_users = sorted(ranked_users, key=lambda x: x['score'], reverse=True)
    return ranked_users

#safe
def insert_data_into_collection(collection_name, data):
    # Validate collection name
    safe_collection = QuerySecurity.validate_input(
        collection_name,
        "collection_name"
    )

    # Validate data structure
    if not isinstance(data, list) or not data:
        raise BadRequest("Data must be a non-empty list")

    # Process and validate each document
    processed_data = []
    for idx, row in enumerate(data, 1):
        if not isinstance(row, dict):
            raise BadRequest(f"Row {idx} must be a dictionary")

        # Validate individual fields if needed
        validated_row = {}
        for k, v in row.items():
            if not isinstance(k, str) or not k.strip():
                raise BadRequest(f"Invalid field name in row {idx}")
            validated_row[k] = v  # Add field-specific validation if needed

        processed_data.append({"data": validated_row})

    try:
        # Perform insertion with timeout protection
        result = db[safe_collection].insert_many(
            processed_data,
            ordered=False  # Continue on errors
        )
        return [str(id) for id in result.inserted_ids]

    except Exception as e:
        # Convert to controlled error
        raise BadRequest(f"Insertion failed: {str(e)}")

#safe
def assign_collection_to_user(username, collection_name):
    # Validate inputs
    safe_username = QuerySecurity.validate_input(username, "username")
    safe_collection = QuerySecurity.validate_input(collection_name, "collection_name")

    # Get user data with secure query
    user_data = db.users.find_one(
        QuerySecurity.secure_query({'username': safe_username})
    )

    if user_data:
        # Secure conversion of string collections to array
        if isinstance(user_data.get('collections'), str):
            db.users.update_one(
                QuerySecurity.secure_query({'username': safe_username}),
                QuerySecurity.secure_query({
                    '$set': {'collections': [user_data['collections']]}
                })
            )

    # Secure final update
    db.users.update_one(
        QuerySecurity.secure_query({'username': safe_username}),
        QuerySecurity.secure_query({
            '$addToSet': {'collections': safe_collection}
        })
    )

#safe
def remove_data_collection(collection_name):
    try:
        # Validate collection name
        safe_collection = QuerySecurity.validate_input(
            collection_name,
            "collection_name")

        # Secure collection operations
        db[safe_collection].drop()

        # Secure config cleanup
        db['config'].delete_one(
            QuerySecurity.secure_query({'collection': safe_collection})
        )

        # Secure user references cleanup
        db.users.update_many(
            QuerySecurity.secure_query({'collections': safe_collection}),
            QuerySecurity.secure_query({'$pull': {'collections': safe_collection}})
        )

        return True
    except Exception:
        # Maintain original error handling
        return False


#safe
def get_assigned_label_db_collection_names(username):
    safe_username = QuerySecurity.validate_input(username, "username")
    if safe_username == 'admin':
        collections = db.list_collection_names()
        items_to_remove = {'users', 'config'}
        collections = list(set(collections) - items_to_remove)
        filtered_list = []
        for collection in collections:
            config = db.config.find_one({'collection': collection})
            # print(config)
            if not config['labels']:
                continue
            filtered_list.append(collection)
        return filtered_list
    else:
        user = users_collection.find_one(QuerySecurity.secure_query({'username': safe_username}))
        collections = user.get("collections")
        user_filtered_list = []
        for collection in collections:
            config = db.config.find_one({'collection': collection})
            # print(config)
            if not config['labels']:
                continue
            user_filtered_list.append(collection)
        return user_filtered_list

#safe
def revoke_collection_from_user(username, collection):
    # Validate inputs using QuerySecurity
    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    safe_collection = QuerySecurity.validate_input(collection, "collection", max_length=64)

    # Execute secure update operation
    db.users.update_one(
        QuerySecurity.secure_query({"username": safe_username}),
        QuerySecurity.secure_query({'$pull': {"collections": safe_collection}})
    )

#safe
def get_unassigned_label_db_collection_names(username):
    safe_username = QuerySecurity.validate_input(username, "username")
    if safe_username == 'admin':
        collections = db.list_collection_names()
        items_to_remove = {'users', 'config'}
        collections = list(set(collections) - items_to_remove)
        filtered_list = []
        for collection in collections:
            config = db.config.find_one({'collection': collection})
            # print(config)
            if config['labels']:
                continue
            filtered_list.append(collection)
        return filtered_list
    else:
        user = users_collection.find_one(QuerySecurity.secure_query({'username': safe_username}))
        collections = user.get("collections")
        user_filtered_list = []
        for collection in collections:
            config = db.config.find_one({'collection': collection})
            # print(config)
            if config['labels']:
                continue
            user_filtered_list.append(collection)
        return user_filtered_list


def change_password(username, password):
    safe_username = QuerySecurity.validate_input(username, "username", max_length=50)
    if not isinstance(password, str):# or len(password) < 8:
        raise BadRequest("Password must be a string with at least 8 characters")

    new_password_hash = generate_password_hash(password)
    # Execute secure update
    result = db.users.update_one(
        QuerySecurity.secure_query({'username': safe_username}),
        {'$set': {'password_hash': new_password_hash}}
    )
    # Check if the user was found and updated
    return result.modified_count == 1
