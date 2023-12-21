import socket
import threading
import logging
import hashlib
import random
import string

THE_FPORT=57545
class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.registry_name = '127.0.0.1'  
        self.registry_port = THE_FPORT   
        self.login_credentials = (None, None)
        self.timer = None

    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))
            self.connected = True
            logging.info(f"Connected to the server at {self.host}:{self.port}")
        except ConnectionRefusedError:
            logging.error("Connection refused. Make sure the server is running.")
        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")

    def send_message(self, message):
        try:
            self.client_socket.send(message.encode())
        except ConnectionError:
            logging.error("Connection to the server lost.")
        except Exception as e:
            logging.error(f"Error sending message: {e}")

    def receive_messages(self):
        try:
            while self.connected:
                logging.info("Waiting to receive messages...")
                data = self.client_socket.recv(1024).decode()
                if not data:
                    logging.info("No message received. Server might have closed the connection.")
                    break  # Connection closed by server

                # Split the data by newline to get individual messages
                messages = data.split('\n')
                for message in messages:
                    if message:  # Ignore empty messages
                        # Handle chat messages differently
                        if message.startswith("CHAT"):
                            print("Chat:", message[5:])
                        else:
                            print("Server:", message)

        except (ConnectionError, OSError) as e:
            logging.error(f"Error receiving messages: {e}")
        finally:
            logging.info("Receive thread is exiting.")
            self.connected = False



   
    def authenticate_user_tcp_client(self):
        try:
            # Receive and handle the authentication challenge from the server
            auth_message = self.client_socket.recv(1024).decode('utf-8')
            if "AUTH CHALLENGE" in auth_message:
                # Create and send an appropriate response
                response = "AUTH RESPONSE"
                self.client_socket.send(response.encode('utf-8'))
                # Wait for server's confirmation
                confirmation = self.client_socket.recv(1024).decode('utf-8')
                if "AUTH CONFIRMED" in confirmation:
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            logging.error(f"Error during authentication: {e}")
            return False


            
    

    def menu_selection(self):
        while True:
            choice = input("Choose: \n1. Create account\n2. Login\n3. Logout\n4. Search\n5. Start a chat\n")
            try:
                if choice == "1":
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    self.create_account(username, password)
                elif choice == "2":
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    peer_server_port = int(input("Enter peer server port: "))
                    self.login(username, password, peer_server_port)
                elif choice == "3":
                    option = int(input("Enter 1 to logout with timer, 2 to logout without timer: "))
                    self.logout(option)
                elif choice == "4":
                    username = input("Enter username to search: ")
                    self.search_user(username)
                elif choice == "5":
                    self.start_chat()
                else:
                    print("Invalid option. Please try again.")
            except ValueError:
                logging.error("Invalid input. Please enter a valid option.")


    def create_account(self, username, password):
        try:
            message = f"JOIN {username} {password}"
            logging.info(f"Sending create account request to {self.registry_name}:{self.registry_port} -> {message}")
            self.client_socket.send(message.encode())
            response = self.client_socket.recv(1024).decode()
            logging.info(f"Received response from {self.registry_name} -> {response}")

            if response == "join-success":
                print("Account created successfully.")
            elif response == "join-exist":
                print("Username already exists. Choose another username or login.")
        except ConnectionError:
            logging.error("Connection to the server lost during account creation.")
        except Exception as e:
            logging.error(f"Error creating account: {e}")


    def login(self, username, password, registry_port):
        try:
            message = f"LOGIN {username} {password} {registry_port}"
            logging.info(f"Sending login request to {self.registry_name}:{self.registry_port} -> {message}")
            self.client_socket.send(message.encode())
            response = self.client_socket.recv(1024).decode()
            logging.info(f"Received response from {self.registry_name} -> {response}")
            if response == "login-success":
                print("Logged in successfully.")
                return 1
            elif response == "login-account-not-exist":
                print("Account does not exist.")
                return 0
            elif response == "login-online":
                print("Account is already online.")
                return 2
            elif response == "login-wrong-password":
                print("Wrong password.")
                return 3
        except ConnectionError:
            logging.error("Connection to the server lost during login.")
        except Exception as e:
            logging.error(f"Error during login: {e}")

    def logout(self, option):
        try:
            if option == 1:
                message = f"LOGOUT {self.login_credentials[0]}"
                self.timer.cancel()
            else:
                message = "LOGOUT"
            logging.info(f"Sending logout request to {self.registry_name}:{self.registry_port} -> {message}")
            self.client_socket.send(message.encode())
        except ConnectionError:
            logging.error("Connection to the server lost during logout.")
        except Exception as e:
            logging.error(f"Error during logout: {e}")


    def start_chat(self):
        print("Enter 'quit' to stop chatting.")
        while True:
            message = input("Enter your message: ")
            if message.lower() == 'quit':
                break
            self.send_message(f"CHAT {message}")

    def search_user(self, username):
        try:
            message = f"SEARCH {username}"
            logging.info(f"Sending search user request to {self.registry_name}:{self.registry_port} -> {message}")
            self.client_socket.send(message.encode())
            response = self.client_socket.recv(1024).decode().split()
            logging.info(f"Received response from {self.registry_name} -> {' '.join(response)}")
            if response[0] == "search-success":
                print(f"{username} is found successfully. IP address: {response[1]}")
                return response[1]
            elif response[0] == "search-user-not-online":
                print(f"{username} is not online.")
                return 0
            elif response[0] == "search-user-not-found":
                print(f"{username} is not found.")
                return None
        except ConnectionError:
            logging.error("Connection to the server lost during search.")
        except Exception as e:
            logging.error(f"Error during search: {e}")

    def run(self):
        try:
            self.connect()
            if not self.connected:
                print("Connection to the server failed.")
                return

            if not self.authenticate_user_tcp_client():
                print("Authentication failed.")
                return

            logging.info("Starting the message receiving thread.")
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            logging.info("Entering the main menu loop.")
            self.menu_selection()
                    
        except Exception as e:
            logging.error(f"Error running client: {e}")
        finally:
            self.connected = False
            self.client_socket.close()
            print("Disconnected from the server.")





if __name__ == "__main__":
    logging.basicConfig(filename="client.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    client = Client('127.0.0.1', THE_FPORT)  
    client.run()
