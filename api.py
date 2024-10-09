from flask import Blueprint, request, jsonify, send_file, flash, current_app
from flask_login import login_required, current_user
from models import find_user, check_password
from flask_login import login_user
from models import get_db_collection_names, import_db_collection, convert_oid
import json
import os
import jwt
from extensions import csrf
from functools import wraps

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
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, *args, **kwargs)

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

        # Use current_app to get the configuration
        token = jwt.encode({'user_id': str(user.id)}, current_app.config['JWT_SECRET_KEY'])

        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401


# API route for downloading a file
@api_bp.route('/api/supervisor/download/<collection_name>', methods=['GET'])
@token_required
def api_download_file(current_user, collection_name):
    print(current_user)
    path = f'static/db/db_{collection_name}.json'
    try:
        return send_file(path, as_attachment=True, download_name=f'extracted_{collection_name}.json')
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# API route for uploading a file
@api_bp.route('/api/supervisor/upload', methods=['POST'])
@login_required
def api_upload_file():
    file = request.files['file']
    file_name_with_extension = file.filename
    file_name = os.path.splitext(file_name_with_extension)[0]

    try:
        data = json.load(file)
        data = convert_oid(data)  # Convert ObjectId if necessary
        if file_name in get_db_collection_names(sys_collections_included=1):
            flash(f'This collection already exists.', 'warning')
        else:
            import_db_collection(file_name, data)
            flash(f'Data collection {file_name} successfully added.', 'success')
        return jsonify({"message": "File uploaded successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
