from flask import request, jsonify
from flask_login import login_user, login_required, current_user

def register_api_routes(app):
    @app.route('/api/login', methods=['POST'])
    def api_login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        # Your logic to authenticate the user
        if username == 'q' and password == 'ww':
            return jsonify({'message': 'Login successful!'}), 200
        return jsonify({'message': 'Invalid credentials'}), 401

    @app.route('/api/data', methods=['GET'])
    @login_required
    def get_data():
        # Example logic to return data
        data = {'key1': 'value1', 'key2': 'value2'}
        return jsonify(data)
