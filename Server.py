import socket
import threading
import logging
from MyDB import DB
import os
import logging.handlers
import filelock
from Client import THE_FPORT

log_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "server.log")

# Create a FileHandler with a FileLock
handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=1024, backupCount=3)
lock_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "lockfile.lock")
file_lock = filelock.FileLock(lock_file_path)

# Acquire the lock before using the file handler
with file_lock:
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

# Now the lock is released, and you can safely use the handler


class RegistryServer:
    def __init__(self, host, port, db):
        self.host = host
        self.port = port
        self.db = db
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.client_handlers = []
        self.client_handlers_lock = threading.Lock()
        

    def start(self):
        logging.info(f"Server listening on {self.host}:{self.port}")
        while True:
            client_socket, address = self.server_socket.accept()
            client_handler = ClientHandler(client_socket, address, self.db, self)  # Pass self as reference
            client_handler.start()
            with self.client_handlers_lock:
                self.client_handlers.append(client_handler)

    def shutdown(self):
        logging.info("Server shutting down.")
        for handler in self.client_handlers:
            handler.close()
        self.db.client.close()  # Close the MongoDB client connection
        self.server_socket.close()
        logging.shutdown()

    def broadcast_message(self, message, sender=None):
        """Broadcasts a message to all authenticated clients."""
        with self.client_handlers_lock:
            for handler in self.client_handlers:
                if handler.is_authenticated and handler != sender:
                    handler.send_message(message)




class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address, db ,registry_server):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = address
        self.username = None
        self.db = db
        self.is_authenticated = False 
        logging.info(f"New connection from: {address}")
        self.registry_server = registry_server


    

    def send_message(self, message):
        try:
            # Append a newline character to delimit the message
            full_message = message + "\n"
            self.client_socket.send(full_message.encode())
        except Exception as e:
            logging.error(f"Error sending message to {self.address}: {e}")

    def run(self):
        try:
            # Perform user authentication
            self.send_message("AUTH CHALLENGE")
            if not self.authenticate_user_tcp_server():
                return  # Authentication failed, close the connection

            while True:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    break  # Connection closed by client

                logging.info(f"Received from {self.address[0]}:{self.address[1]}: {message}")
                self.handle_message(message)

                if self.is_authenticated:
                    self.handle_message(message)
                else:
                    self.authenticate_user_tcp_server()

        except KeyboardInterrupt:
            logging.info(f"KeyboardInterrupt: Closing connection with {self.address}")
        except Exception as e:
            logging.error(f"Error handling client {self.address[0]}:{self.address[1]}: {e}")

        logging.info(f"Connection from {self.address[0]}:{self.address[1]} closed.")
        self.close()

    def authenticate_user_tcp_server(self):
        try:
            # Send an authentication challenge
            challenge = "AUTH CHALLENGE"
            self.send_message(challenge)
            logging.info(f"Sent Authentication Challenge: {challenge}")

            # Wait for the client's response
            response = self.client_socket.recv(1024).decode('utf-8')
            logging.info(f"Received Authentication Response: {response}")

            # Check if the response is what we expect
            if "AUTH RESPONSE" in response:
                self.send_message("AUTH CONFIRMED")
                logging.info("Authentication successful.")
                return True
            else:
                self.send_message("AUTH FAILED")
                logging.error("Authentication failed.")
                return False
        except Exception as e:
            logging.error(f"Error during authentication: {e}")
            return False


    

    def handle_message(self, message):
        try:
            command, *args = message.split()

            # Handle each command by calling the appropriate method
            if command == "JOIN":
                self.handle_join(args)
            elif command == "LOGIN":
                self.handle_login(args)
            elif command == "LOGOUT":
                self.handle_logout(args)
            elif command == "SEARCH":
                self.handle_search(args)
            elif command == "CHAT":
                # For chat messages, pass the entire message after the command
                chat_message = " ".join(args)
                self.handle_chat(chat_message)
            else:
                # Send a message back to the client if the command is not recognized
                self.send_message(f"Invalid command: {command}")

        except Exception as e:
            # Log any exceptions that occur while handling the message
            logging.error(f"Error handling message from {self.address}: {e}")


    def handle_join(self, args):
        if len(args) != 2:
            self.send_message("Invalid JOIN command. Usage: JOIN <username> <password>")
            return
        username, password = args
        if self.db.is_account_exist(username):
            self.send_message("join-exist")
        else:
            if self.db.register(username, password):
                self.send_message("join-success")
                logging.info(f"User {username} registered successfully.")
            else:
                self.send_message("join-failed")
                logging.error(f"Failed to register user {username}")


    def handle_login(self, args):
        if len(args) != 3:
            self.send_message("Invalid LOGIN command. Usage: LOGIN <username> <password> <ip:port>")
            return

        username, password, peer_address = args
        if not self.db.is_account_exist(username):
            self.send_message("login-account-not-exist")
        elif self.db.is_account_online(username):
            self.send_message("login-online")
        elif self.db.get_password(username) == password:
            self.username = username
            self.db.user_login(username, *peer_address.split(':'))
            self.send_message("login-success")
            logging.info(f"User {username} logged in from {peer_address}")
        else:
            self.send_message("login-wrong-password")

    def handle_logout(self, args):
        if len(args) != 1:
            self.send_message("Invalid LOGOUT command. Usage: LOGOUT <username>")
            return
        username = args[0]
        if self.db.is_account_online(username):
            self.db.user_logout(username)
            self.send_message(f"{username} logged out")
            self.close()
        else:
            self.send_message(f"{username} not online")

    def handle_search(self, args):
        if len(args) != 1:
            self.send_message("Invalid SEARCH command. Usage: SEARCH <username>")
            return

        username = args[0]
        if self.db.is_account_exist(username):
            if self.db.is_account_online(username):
                peer_info = self.db.get_peer_ip_port(username)
                self.send_message(f"search-success {peer_info[0]}:{peer_info[1]}")
            else:
                self.send_message("search-user-not-online")
        else:
            self.send_message("search-user-not-found")

    def close(self):
        try:
            self.client_socket.close()
        except Exception as e:
            logging.error(f"Error closing connection with {self.address}: {e}")


    def handle_chat(self, message):
        # Ensuring the user is authenticated before sending the chat message
        if not self.is_authenticated:
            logging.error("Unauthorized chat attempt by an unauthenticated client.")
            self.send_message("You need to be authenticated to send chat messages.")
            return

        # Format the message with the username and ensure it's properly sanitized or limited in length
        chat_message = f"{self.username}: {message[:500]}"  # Limit message length for example

        # Log the chat message for audit or debugging purposes
        logging.info(f"Broadcasting chat message from {self.username}")

        # Broadcast the message to all authenticated clients
        self.registry_server.broadcast_message(chat_message, sender=self)




def main():
    logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create and initialize the MongoDB database
    db = DB()
    if not db.is_connection_working():
        logging.error("Server shutting down due to database connection issues.")
        return
    # Start the registry server
    registry_server = RegistryServer('127.0.0.1', THE_FPORT, db)
    try:
        registry_server.start()
    except KeyboardInterrupt:
        registry_server.shutdown()

if __name__ == "__main__":
    
    main()
