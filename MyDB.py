import logging
import hashlib
import os
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import datetime
import socket



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
        if self.is_account_exist(username):
            return False

        salt = os.urandom(16)
        hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
        account = {'username': username, 'password': hashed_password, 'salt': salt, 'online': False}
        self.db.accounts.insert_one(account)
        return True

    def validate_login(self, username, password):
        user = self.db.accounts.find_one({"username": username})
        if user:
            hashed_password = hashlib.sha256(user["salt"] + password.encode()).hexdigest()
            return hashed_password == user["password"]
        return False
    
    def authenticate_user(self, username, password):
        """
        Authenticate a user by verifying their username and password.
        Returns True if the user is authenticated, False otherwise.
        """
        # First, check if the account exists
        if not self.is_account_exist(username):
            logging.info(f"Authentication failed: User {username} does not exist.")
            return False

        # Validate the login credentials
        if self.validate_login(username, password):
            logging.info(f"User {username} successfully authenticated.")
            return True
        else:
            logging.info(f"Authentication failed: Incorrect password for user {username}.")
            return False
    
    
    def user_login(self, username, ip, port, udp_ip, udp_port ):
        try:
            # Update the user's TCP and UDP address in a single operation
            self.db.accounts.update_one(
                {'username': username},
                {'$set': {'online': True, 'ip': ip, 'port': port, 'udp_ip': udp_ip, 'udp_port': udp_port}}
            )
            logging.info(f"User {username} logged in with TCP and UDP address and marked as online.")
        except Exception as e:
            logging.error(f"Error in user_login: {e}")

    def user_logout(self, username):
        try:
            # Clear only the TCP address and mark the user as offline
            self.db.accounts.update_one(
                {'username': username},
                {'$set': {'online': False, 'ip': None, 'port': None}}
            )
            logging.info(f"User {username} logged out and marked as offline.")
        except Exception as e:
            logging.error(f"Error in user_logout: {e}")

    def get_peer_addresses(self, username):
        """ Retrieve both TCP and UDP IP and port of an online user """
        try:
            user = self.db.accounts.find_one({'username': username, 'online': True}, {'ip': 1, 'port': 1, 'udp_ip': 1, 'udp_port': 1})
            if user:
                return {'tcp_ip': user['ip'], 'tcp_port': user['port'], 'udp_ip': user['udp_ip'], 'udp_port': user['udp_port']}
            else:
                return None
        except Exception as e:
            logging.error(f"Error in get_peer_addresses: {e}")
            return None



    def is_account_online(self, username):
        """ Check if a user is currently online """
        try:
            user = self.db.accounts.find_one({'username': username}, {'online': 1})
            return user and user.get('online', False)
        except Exception as e:
            logging.error(f"Error in is_account_online: {e}")
            return False
        

    def create_chat_room(self, chat_room_name, creator_username, creator_udp_ip, creator_udp_port):
        if self.db.chat_rooms.count_documents({'name': chat_room_name}) > 0:
            logging.info(f"Chat room '{chat_room_name}' already exists.")
            return False

        chat_room = {
            'name': chat_room_name,
            'creator': creator_username,
            'members': [{'username': creator_username, 'udp_ip': creator_udp_ip, 'udp_port': creator_udp_port}]
        }
        self.db.chat_rooms.insert_one(chat_room)
        logging.info(f"Chat room '{chat_room_name}' created successfully.")
        return True
    

    def is_valid_udp_address(self, ip, port):
        """ Validate the UDP IP and port format """
        try:
            # Validate IP format
            socket.inet_aton(ip)
            # Validate port number (should be an integer in the range 0-65535)
            if not 0 <= int(port) <= 65535:
                raise ValueError("Invalid port number")
            return True
        except Exception as e:
            logging.error(f"Invalid UDP address: {e}")
            return False

    
    def add_to_chat_room(self, chat_room_name, username, udp_ip, udp_port):
        if not self.is_valid_udp_address(udp_ip, udp_port):
            logging.error(f"Cannot add to chat room: Invalid UDP address for {username}")
            return False
        try:
            member_info = {'username': username, 'udp_ip': udp_ip, 'udp_port': udp_port}
            self.db.chat_rooms.update_one(
                {'name': chat_room_name},
                {'$addToSet': {'members': member_info}}
            )
            logging.info(f"Added {username} with UDP info to chat room {chat_room_name}.")
        except Exception as e:
            logging.error(f"Error in add_to_chat_room: {e}")


    def remove_from_chat_room(self, chat_room_name, username, udp_ip, udp_port):
        if not self.is_valid_udp_address(udp_ip, udp_port):
            logging.error(f"Cannot remove from chat room: Invalid UDP address for {username}")
            return False
        try:
            member_info = {'username': username, 'udp_ip': udp_ip, 'udp_port': udp_port}
            self.db.chat_rooms.update_one(
                {'name': chat_room_name},
                {'$pull': {'members': member_info}}
            )
            logging.info(f"Removed {username} with UDP info from chat room {chat_room_name}.")
        except Exception as e:
            logging.error(f"Error in remove_from_chat_room: {e}")


    def post_message(self, room_name, message, peer_id):
        """
        Post a message in a chat room.
        """
        try:
            self.db.messages.insert_one({
                'room_name': room_name, 
                'message': message, 
                'sender': peer_id, 
                'timestamp': datetime.datetime.utcnow()
            })
            logging.info(f"Message posted in chat room '{room_name}' by peer '{peer_id}'.")
            return True
        except Exception as e:
            logging.error(f"Error posting message in chat room '{room_name}': {e}")
            return False

    def get_messages(self, room_name):
        """
        Retrieve messages from a chat room.
        """
        try:
            messages = list(self.db.messages.find(
                {'room_name': room_name}, 
                {'_id': 0, 'room_name': 0}
            ).sort('timestamp', 1))
            logging.info(f"Retrieved messages from chat room '{room_name}'.")
            return messages
        except Exception as e:
            logging.error(f"Error retrieving messages from chat room '{room_name}': {e}")
            return []

