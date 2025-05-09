from dotenv import load_dotenv
import os
# from flask import Config
from pymongo import MongoClient
from bson import SON, ObjectId
from werkzeug.exceptions import BadRequest
import re

# Load environment variables from .env file
load_dotenv()


class QuerySecurity:
    """Silent security validation for MongoDB queries"""

    # Allowed MongoDB query operators (whitelist)
    ALLOWED_OPERATORS = {
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
        '$in', '$nin', '$and', '$or', '$not', '$exists'
    }

    @staticmethod
    def validate_input(value, field_name, max_length=100):
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


class ConfigDB():
    MONGODB_URI = os.getenv('MONGODB_URI')
    MONGO_DBNAME = os.getenv('MONGO_DBNAME')

    @classmethod
    def _get_db_connection(cls):
        """Secure DB connection helper"""
        client = MongoClient(cls.MONGODB_URI)
        return client[cls.MONGO_DBNAME]

    @classmethod
    def _validate_collection_name(cls, name):
        """Special validation for collection names that allows initial setup"""
        try:
            return QuerySecurity.validate_input(name, "collection_name", max_length=120)
        except BadRequest:
            # Allow through for initial setup, but still sanitize
            if isinstance(name, str):
                return name.strip()[:120]
            raise BadRequest("Invalid collection name format")

    @classmethod
    def get_data_labels(cls, data_collection):
        db = cls._get_db_connection()
        config_collection = db.config

        safe_collection = cls._validate_collection_name(data_collection)
        result = config_collection.find_one(
            {'collection': safe_collection}  # Simplified for initial setup
        )

        return result.get('labels') if result else None

    @classmethod
    def update_data_labels(cls, data_collection, new_labels):
        db = cls._get_db_connection()
        config_collection = db.config

        safe_collection = cls._validate_collection_name(data_collection)

        # More permissive validation for initial labels
        if not isinstance(new_labels, (list, dict)):
            raise BadRequest("Labels must be a list or dictionary")

        if config_collection.find_one({"collection": safe_collection}):
            config_collection.update_one(
                {"collection": safe_collection},
                {"$set": {"labels": new_labels}}
            )
        else:
            config_collection.insert_one({
                "collection": safe_collection,
                "labels": new_labels
            })
        return True

    @classmethod
    def set_num_required_labels(cls, data_collection, num_required_labels):
        db = cls._get_db_connection()
        config_collection = db.config

        safe_collection = cls._validate_collection_name(data_collection)

        try:
            num = int(num_required_labels)
        except (ValueError, TypeError):
            raise BadRequest("num_required_labels must be an integer")

        update_data = {
            "collection": safe_collection,
            "num_required_labels": num
        }

        if config_collection.find_one({"collection": safe_collection}):
            config_collection.update_one(
                {"collection": safe_collection},
                {"$set": {"num_required_labels": num}}
            )
        else:
            config_collection.insert_one(update_data)
        return True

    @classmethod
    def set_num_labels(cls, data_collection, num_labels):
        db = cls._get_db_connection()
        config_collection = db.config

        safe_collection = cls._validate_collection_name(data_collection)

        try:
            num = int(num_labels)
        except (ValueError, TypeError):
            raise BadRequest("num_labels must be an integer")

        update_data = {
            "collection": safe_collection,
            "num_labels": num
        }

        if config_collection.find_one({"collection": safe_collection}):
            config_collection.update_one(
                {"collection": safe_collection},
                {"$set": {"num_labels": num}}
            )
        else:
            config_collection.insert_one(update_data)
        return True


class ConfigApp:
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CORS_ORIGINS = "*"
    SECRET_KEY = os.getenv('SECRET_KEY')
    WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    # cert = 'localhost.crt'
    # key = 'localhost.key'
