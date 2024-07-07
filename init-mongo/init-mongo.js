const fs = require('fs');

// Read the JSON file
const data_config = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/config.json', 'utf8'));
const data_data = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/data.json', 'utf8'));
const data_users = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/users.json', 'utf8'));

db = db.getSiblingDB('DataLabeling');

if (!db.getCollectionNames().includes('config')) {
  db.config.insertMany(data_config);
}

if (!db.getCollectionNames().includes('data')) {
  db.data.insertMany(data_data);
}

if (!db.getCollectionNames().includes('users')) {
  db.users.insertMany(data_users);
}
