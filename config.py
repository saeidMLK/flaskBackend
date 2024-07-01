from dotenv import load_dotenv
import os
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()


class ConfigDB():
    MONGODB_URI = os.getenv('MONGODB_URI')
    MONGO_DBNAME = os.getenv('MONGO_DBNAME')
    @classmethod
    def get_data_labels(cls):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        labels = config_collection.find_one({'key': 'labels'})
        return labels['value']

    @classmethod
    def update_data_labels(cls, new_labels):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        return config_collection.update_one(
                {"key": "labels"},
                {"$set": {"value": new_labels}})


class ConfigApp:
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CORS_ORIGINS = "*"
    SECRET_KEY = os.getenv('SECRET_KEY')
    WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY')
    # cert = 'localhost.crt'
    # key = 'localhost.key'

