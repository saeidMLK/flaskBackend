const fs = require('fs');

// Read the JSON file
const data_config = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/config.json', 'utf8'));
const data_QAs = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/QAs.json', 'utf8'));
const data_users = JSON.parse(fs.readFileSync('/docker-entrypoint-initdb.d/users.json', 'utf8'));

db = db.getSiblingDB('FAQs');

if (!db.getCollectionNames().includes('config')) {
  db.config.insertMany(data_config);
}

if (!db.getCollectionNames().includes('QAs')) {
  db.QAs.insertMany(data_QAs);
}

if (!db.getCollectionNames().includes('users')) {
  db.users.insertMany(data_users);
}
