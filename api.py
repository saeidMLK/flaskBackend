from flask import Blueprint, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
from models import find_user, check_password, set_data_configs
from flask_login import login_user
import json
import os
import jwt
from extensions import csrf
from functools import wraps
from models import get_user_collection, extract_db_collection, get_db_collection_names, import_db_collection, convert_oid


# Define a Blueprint
api_bp = Blueprint('api', __name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            # Decode token and get user_id and username
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
            current_username = data['username']  # Get the username from the token
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, current_username, *args, **kwargs)

    return decorated


@api_bp.route('/api/login', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = find_user(username)

    if user and check_password(user, password):
        login_user(user)

        # Include both user_id and username in the token
        token = jwt.encode({'user_id': str(user.id), 'username': user.username}, current_app.config['JWT_SECRET_KEY'])

        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401


@api_bp.route('/api/supervisor/download/<collection_name>', methods=['GET'])
@token_required
def api_download_file(current_user, current_username, collection_name):
    # print(f"User ID: {current_user}, Username: {current_username}")
    if collection_name in get_user_collection(current_username):
        # print(f"Collection name: {collection_name}")
        try:
            path = f'static/db/db_{collection_name}.json'
            extract_db_collection(path, collection_name)
            return send_file(path, as_attachment=True, download_name=f'extracted_{collection_name}.json')
        except FileNotFoundError:
            return jsonify({"error": "File not found"}), 404
    else:
        return jsonify({"error": "Collection not found"}), 404


@api_bp.route('/api/supervisor/upload', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route
@token_required
def api_upload_file(current_user, current_username):
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    file_name_with_extension = file.filename
    file_name = os.path.splitext(file_name_with_extension)[0]  # Get the collection name from the file

    try:
        # Load and convert data from the uploaded file
        data = json.load(file)
        # Ensure the data is either a list or an object
        if not isinstance(data, (dict, list)):
            return jsonify({"error": "Uploaded file must contain a valid JSON object or an array of objects."}), 400
        # If the data is a single object, wrap it in a list to maintain consistency
        if isinstance(data, dict):
            data = [data]
        data = convert_oid(data)  # Convert any ObjectId fields, if necessary

        # Check if the collection already exists
        if file_name in get_db_collection_names(sys_collections_included=1):
            return jsonify({"error": "This collection already exists."}), 400

        # Import the data collection into MongoDB
        import_db_collection(current_username, file_name, data)

        return jsonify(
            {"message": f"Data collection {file_name} uploaded successfully with default configurations."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@api_bp.route('/api/supervisor/set_configs', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route
@token_required
def api_set_data_configs(current_user, current_username):
    try:
        # Parse the JSON body from the request
        config_data = request.json

        # Extract collection name, labels, and num_required_labels from the request
        file_name = config_data.get('collection_name')
        labels = config_data.get('labels', [])
        num_required_labels = config_data.get('num_required_labels', 1)

        if not file_name:
            return jsonify({"error": "collection_name is required"}), 400

        # Validate that the collection exists
        # if file_name not in get_db_collection_names(sys_collections_included=1):
        if file_name not in get_user_collection(current_username):
            return jsonify({"error": f"Collection {file_name} does not exist."}), 404

        # Convert labels to JSON string for set_data_configs function
        labels_json = json.dumps(labels)  # Convert the list to JSON string

        # Update the collection's configuration in MongoDB
        set_data_configs(file_name, labels_json, num_required_labels)

        return jsonify({"message": f"Configurations for collection {file_name} updated successfully."}), 200

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500