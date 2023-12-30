
from socket import *
import threading
import select
import logging
from MyDB import DB

# This class is used to process the peer messages sent to registry
# for each peer connected to registry, a new client thread is created
class ClientThread(threading.Thread):
    def __init__(self, ip, port, tcpClientSocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.tcpClientSocket = tcpClientSocket
        self.username = None
        self.isOnline = True
        self.lock = threading.Lock()  # Initialize the lock here
        print(f"New thread started for {ip}:{port}")

    def run(self):
        print(f"Connection from: {self.ip}:{self.port}")
        while True:
            try:
                # Waits for incoming messages from peers
                message = self.tcpClientSocket.recv(1024).decode().split()
                if not message:
                    break  # Break if an empty message is received (client disconnected)

                logging.info(f"Received from {self.ip}:{self.port} -> {' '.join(message)}")

                # JOIN operation
                if message[0] == "JOIN":
                    if db.is_account_exist(message[1]):
                        response = "join-exist"
                    else:
                        db.register(message[1], message[2])
                        response = "join-success"
                    self.tcpClientSocket.send(response.encode())

                # LOGIN operation
                elif message[0] == "LOGIN":
                    # Extract username and password from the message
                    username, password = message[1], message[2]
                    # Use the authenticate_user method for authentication
                    if db.authenticate_user(username, password):
                        # User is authenticated, proceed with login operations
                        self.username = username
                        self.lock.acquire()
                        try:
                            tcpThreads[self.username] = self
                        finally:
                            self.lock.release()
                        db.user_login(username, self.ip, message[3])  # assuming message[3] is the port
                        response = "login-success"
                    else:
                        # Check if the user account doesn't exist or password is incorrect
                        if not db.is_account_exist(username):
                            response = "login-account-not-exist"
                        else:
                            response = "login-wrong-password"
                    self.tcpClientSocket.send(response.encode())


                # LOGOUT operation
                elif message[0] == "LOGOUT":
                    if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
                        db.user_logout(message[1])
                        self.lock.acquire()
                        try:
                            if message[1] in tcpThreads:
                                del tcpThreads[message[1]]
                        finally:
                            self.lock.release()
                        self.tcpClientSocket.close()
                        break
                    else:
                        self.tcpClientSocket.close()
                        break

                # SEARCH operation
                elif message[0] == "SEARCH":
                    if db.is_account_exist(message[1]):
                        if db.is_account_online(message[1]):
                            peer_info = db.get_peer_ip_port(message[1])
                            response = f"search-success {peer_info[0]}:{peer_info[1]}"
                        else:
                            response = "search-user-not-online"
                    else:
                        response = "search-user-not-found"
                    self.tcpClientSocket.send(response.encode())

                # CHAT operation
                elif message[0] == "CHAT":
                    target_username = message[1]
                    if db.is_account_online(target_username):
                        target_peer_info = db.get_peer_addresses(target_username)
                        response = f"chat-success {target_peer_info['tcp_ip']}:{target_peer_info['tcp_port']} {target_peer_info['udp_ip']}:{target_peer_info['udp_port']}"
                    else:
                        response = "chat-user-not-online"
                    self.tcpClientSocket.send(response.encode())


                # CREATE CHAT ROOM operation
                elif message[0] == "CREATE_CHAT_ROOM":
                    chat_room_name = message[1]  # The name of the chat room to create
                    if db.create_chat_room(chat_room_name, self.username):
                        response = f"chat-room-created {chat_room_name}"
                    else:
                        response = "chat-room-already-exists"
                    self.tcpClientSocket.send(response.encode())

                # JOIN_CHAT_ROOM operation
                elif message[0] == "JOIN_CHAT_ROOM":
                    chat_room_name, username = message[1], self.username
                    udp_ip, udp_port = message[2], int(message[3])  # Assuming UDP IP and port are part of the message
                    if db.add_to_chat_room(chat_room_name, username, udp_ip, udp_port):
                        response = f"joined-chat-room {chat_room_name}"
                        # Send UDP address info of all members in the chat room to the joining member
                        participants = db.get_chat_room_participants(chat_room_name)
                        participant_info = ";".join([f"{p['username']} {p['udp_ip']}:{p['udp_port']}" for p in participants])
                        self.tcpClientSocket.send(f"{response} {participant_info}".encode())
                    else:
                        response = "failed-join-chat-room"
                        self.tcpClientSocket.send(response.encode())


                # LEAVE_CHAT_ROOM operation
                elif message[0] == "LEAVE_CHAT_ROOM":
                    chat_room_name, username = message[1], self.username
                    udp_ip, udp_port = db.get_udp_address(username)  # Retrieve UDP info from DB
                    if db.remove_from_chat_room(chat_room_name, username, udp_ip, udp_port):
                        response = f"left-chat-room {chat_room_name}"
                    else:
                        response = "failed-leave-chat-room"
                    self.tcpClientSocket.send(response.encode())


                # POST_MESSAGE operation
                elif message[0] == "POST_MESSAGE":
                    chat_room_name, peer_message = message[1], ' '.join(message[2:])
                    if db.post_message(chat_room_name, peer_message, self.username):
                        response = "message-posted-successfully"
                    else:
                        response = "failed-to-post-message"
                    self.tcpClientSocket.send(response.encode())

                # GET_MESSAGES operation
                elif message[0] == "GET_MESSAGES":
                    chat_room_name = message[1]
                    messages = db.get_messages(chat_room_name)
                    response = f"chat-messages {chat_room_name} " + ' '.join(messages)
                    self.tcpClientSocket.send(response.encode())



            except OSError as oErr:
                logging.error(f"OSError: {oErr}")
                break



print("Registry started...")
port = 15601
hostname = gethostname()
try:
    host = gethostbyname(hostname)
except gaierror:
    import netifaces as ni
    host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

print(f"Registry IP address: {host}")
print(f"Registry port number: {port}")

db = DB()
tcpThreads = {}
tcpSocket = socket(AF_INET, SOCK_STREAM)
tcpSocket.bind((host, port))
tcpSocket.listen(5)
inputs = [tcpSocket]
logging.basicConfig(filename="registry.log", level=logging.INFO)

while inputs:
    print("Listening for incoming connections...")
    readable, _, _ = select.select(inputs, [], [])
    for s in readable:
        if s is tcpSocket:
            tcpClientSocket, addr = tcpSocket.accept()
            newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
            newThread.start()

tcpSocket.close()