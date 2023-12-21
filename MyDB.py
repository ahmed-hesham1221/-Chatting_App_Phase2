
import logging
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import hashlib
import os

# Includes database operations
class DB:

    def __init__(self, connection_string='mongodb+srv://AhmedsDB:ahmed1@cluster0.pyefwwr.mongodb.net/?retryWrites=true&w=majority', db_name='MyApp'):
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
       

    def is_connection_working(self):
        try:
            self.client.server_info()
            logging.info("Connection to the database is working")
            return True
        except ServerSelectionTimeoutError:
            logging.error("Connection to the database is not working.")
            return False

    def is_account_exist(self, username):
        count = self.db.accounts.count_documents({'username': username})
        return count > 0

    def register(self, username, password):
        # Generate a random salt
        salt = os.urandom(16)
        # Hash the password using the generated salt
        hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
        # Create the account document with username, hashed password, salt, and online status
        account = {
            'username': username,
            'password': hashed_password,
            'salt': salt,
            'online': False
        }
        # Insert the account document into the 'accounts' collection
        try:
            self.db.accounts.insert_one(account)
            logging.info(f"User {username} registered successfully.")
            return True
        except Exception as e:
            logging.error(f"Error registering user {username}: {e}")
            return False


    def get_password(self, username):
        user = self.db.accounts.find_one({"username": username})
        return user["password"] if user else None

    def is_account_online(self, username):
        return self.db.online_peers.count_documents({"username": username}) > 0

    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.db.online_peers.insert_one(online_peer)

    def user_logout(self, username):
        self.db.online_peers.delete_one({"username": username})

    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"]) if res else None
    

x = DB()
# x.is_connection_working()
if x.is_connection_working():
    if x.register("test_user", "password"):
        print("Account created successfully!")
    else:
        print("Error creating account.")
else:
    print("Connection to the database is not working.")