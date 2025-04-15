import json

from pymongo import MongoClient
import base64

from config import ConfigDB
from models import convert_oid, set_data_state

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['DataLabeling']
collection = db['image']

# Correct file path (ensure this is a string, not a tuple)
image_path = "./static/images/bg-1.jpg"  # Make sure this is the actual path


# Option 2: Storing base64-encoded image
with open(image_path, "rb") as image_file:
    encoded_image = base64.b64encode(image_file.read()).decode('utf-8')
# print(encoded_image)
# Create the document in the desired format
document_with_image = {
    "data": {
        "image_name": "image.jpg",
        "image_data": encoded_image,
        "description": "An example image in base64 format"
    }
}

# Insert the document into the collection
collection.insert_one(document_with_image)

print("Image data inserted successfully in the desired format.")


def import_db_collection(username, collection_name, data):
    # Update the user's collections in the "users" collection
    db.users.update_one(
        {'username': username},
        {'$addToSet': {'collections': collection_name}}  # Add the collection name if it's not already present, add collaction name in user profile
    )
    # Add dataset to db
    data = convert_oid(data)
    db[collection_name].insert_many(data)

    # Set initial configs for new dataset
    ConfigDB.update_data_labels(collection_name, [])
    ConfigDB.set_num_labels(collection_name, 0)
    ConfigDB.set_num_required_labels(collection_name, 1)
    return set_data_state(collection_name)



# Load data from the local JSON file
def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data

# Specify the path to your JSON file
json_file_path = './static/mage.json'

# Load the JSON data
json_data = load_json_file(json_file_path)

# Import the data into the 'data_old' collection
# import_db_collection('xx','ww2', json_data)


# Function to retrieve image from the database
def get_image_from_db(image_name):
    # Find the image by its name
    image_data = db['ww'].find_one({'data.image_name': image_name})

    if image_data:
        # Get the base64 image data
        base64_image = image_data['data']['image_data']
        # Decode the base64 string into bytes
        image_bytes = base64.b64decode(base64_image)
        return image_bytes
    return None


# get_image_from_db('image')

# Function to read and encode the audio file
def encode_audio(file_path):
    with open(file_path, 'rb') as audio_file:
        print(11111111111111000000000000000000000000)
        encoded_audio = base64.b64encode(audio_file.read()).decode('utf-8')
        print(encoded_audio)
    return encoded_audio

encode_audio('./static/rec6.wav')


