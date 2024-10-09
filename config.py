from dotenv import load_dotenv
import os
# from flask import Config
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()


class ConfigDB():
    MONGODB_URI = os.getenv('MONGODB_URI')
    MONGO_DBNAME = os.getenv('MONGO_DBNAME')

    @classmethod
    def get_data_labels(cls, data_collection):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        result = config_collection.find_one({'collection': data_collection})
        if result:
            labels = result['labels']
            return labels

    @classmethod
    def update_data_labels(cls, data_collection, new_labels):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        if config_collection.find_one({"collection": data_collection}):
            return config_collection.update_one(
                {"collection": data_collection},
                {"$set": {"labels": new_labels}})
        else:
            return config_collection.insert_one({"collection": data_collection,
                                                 "labels": new_labels})

    @classmethod
    def set_num_required_labels(cls, data_collection, num_required_labels):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        if config_collection.find_one({"collection": data_collection}):
            return config_collection.update_one(
                {"collection": data_collection},
                {"$set": {"num_required_labels": num_required_labels}})
        else:
            return config_collection.insert_one({"collection": data_collection,
                                                 "num_required_labels": num_required_labels})

    @classmethod
    def set_num_labels(cls, data_collection, num_labels):
        client = MongoClient(ConfigDB.MONGODB_URI)
        db = client[ConfigDB.MONGO_DBNAME]
        config_collection = db.config
        if config_collection.find_one({"collection": data_collection}):
            return config_collection.update_one(
                {"collection": data_collection},
                {"$set": {"num_labels": num_labels}})
        else:
            return config_collection.insert_one({"collection": data_collection,
                                                 "num_labels": num_labels})


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
