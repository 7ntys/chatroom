import hashlib
import smtplib
import random
from email.message import EmailMessage
import sqlite3
import socket
import threading
import ssl
from datetime import datetime
import base64
import io  # Add io import for handling byte data
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# SQLite Database Initialization

# Pour maintenir la liste des clients connectés par chatroom
clients_by_room = {}
verification_codes = {}
# Client Handler
def handle_client(client_socket, addr):
    print(f"Client connected: {addr}")
    current_room_id = None
    current_user_id = None
    try:
        while True:
            # Receive request from the client
            request = client_socket.recv(1024).decode().strip()
            if not request:
                break  # Connection closed by the client

            print(f"Received request: {request}")

            # Parse request
            command, *params = request.split()

            # Handle different types of requests
            if command == "LOGIN":
                username, password = params
                response = handle_login(username, password)

                if response == "LOGIN_SUCCESS":
                    code = generate_verification_code()
                    email = get_user_email(username)
                    send_verification_code(email, code)
                    verification_codes[username] = code
                    print(verification_codes)
                    client_socket.sendall("VERIFICATION_CODE_SENT".encode())
                else:
                    client_socket.sendall(response.encode())
            elif command == "VERIFY_CODE":
                code, username = params
                if str(verification_codes.get(username)) == str(code):
                    current_user_id = username
                    print(verification_codes.get(username))
                    client_socket.sendall("VERIFY_SUCCESS".encode())
                else:
                    client_socket.sendall("VERIFICATION_FAILED".encode())
            elif command == "REGISTER":
                username, password, email = params
                response = handle_register(username, password, email)
                client_socket.sendall(response.encode())


            elif command == "LIST_ROOMS":
                response = handle_list_rooms()
                client_socket.sendall(response.encode())

            elif command == "JOIN_ROOM":
                room_id, room_code = params
                response = handle_join_room(room_id, room_code)
                current_room_id = room_id
                if room_id not in clients_by_room:
                    clients_by_room[room_id] = []
                clients_by_room[room_id].append(client_socket)
                client_socket.sendall(response.encode())

            elif command == "LIST_MESSAGES":
                room_id = params[0]
                response = handle_list_messages(room_id)
                client_socket.sendall(response.encode())

            elif command == "SEND_MESSAGE":
                room_id, username, message = params[0], params[1], " ".join(params[2:])
                response = handle_send_message(room_id, username, message)
                client_socket.sendall(response.encode())
                if response == "SEND_MESSAGE_SUCCESS":
                    print(f"Broadcasting message to room {room_id}, having those id connected : {clients_by_room}")
                    broadcast_message(client_socket ,room_id, username, message)

            elif command == "SEND_IMAGE":
                room_id, username, image_name, encoded_image = params[0], params[1], params[2], params[3]
                response = handle_send_image(room_id, username, image_name, encoded_image)
                client_socket.sendall(response.encode())

            # Add more commands as needed

            else:
                client_socket.sendall(b"INVALID_COMMAND")

    except Exception as e:
        print(f"Error handling client: {e}")


    finally:
        print(f"Client disconnected: {addr}")
        if current_room_id and client_socket in clients_by_room.get(current_room_id, []):
            clients_by_room[current_room_id].remove(client_socket)
        client_socket.close()


# Request Handlers
def handle_login(username, password):
    conn = sqlite3.connect('chatroom.db')
    cursor = conn.cursor()
    print(password)
    print(hashlib.sha256(password.encode()).hexdigest)
    cursor.execute("SELECT * FROM Users WHERE username = ? AND password = ?", (username, hashlib.sha256(password.encode()).hexdigest()
))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        return "LOGIN_SUCCESS"
    else:
        return "LOGIN_FAILURE"

def broadcast_message(client_socket,room_id, username, message):
    formatted_message = f"MESSAGE_INCOMING {datetime.today()}${username}${message}"
    print(f"Broadcasting message: {formatted_message}")
    for client in clients_by_room.get(room_id, []):
        try:
            print(f"Sending message to client: {client}, from client: {client_socket}")
            if client != client_socket:
                print(f"Identity verified")
                client.sendall(formatted_message.encode())
        except Exception as e:
            print(f"Error broadcasting message to client: {e}")


def handle_list_messages(room_id):
    conn = sqlite3.connect('chatroom.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT Users.username, Messages.message_text, Messages.created_at FROM Messages JOIN Users ON Messages.user_id = Users.user_id WHERE Messages.room_id = ?",
        (room_id,))
    messages = cursor.fetchall()
    print(messages)
    cursor.close()
    conn.close()

    if messages:
        message_list = "\n".join([f"{message[2]} %ù% {message[0]} %ù% {message[1]}$" for message in messages])
        return f"MESSAGE_LIST\n{message_list}"
    else:
        return "NO_MESSAGES_AVAILABLE"



def handle_register(username, password, email):

    try:
        conn = sqlite3.connect('chatroom.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Users (username, password, email) VALUES (?, ?, ?)", (username, hashlib.sha256(password.encode()).hexdigest(), email
))
        conn.commit()
        cursor.close()
        conn.close()

        code = generate_verification_code()
        send_verification_code(decrypt(key, email), code)
        verification_codes[username] = code

        return "REGISTER_SUCCESS"
    except sqlite3.IntegrityError:
        return "REGISTER_FAILURE: Username already exists"


def handle_list_rooms():
    conn = sqlite3.connect('chatroom.db')
    cursor = conn.cursor()
    cursor.execute("SELECT room_id, room_name, description FROM ChatRooms")
    rooms = cursor.fetchall()
    cursor.close()
    conn.close()

    # Format the room list as a string to send to the client
    if rooms:
        room_list = "\n".join([f"{room[0]}: {room[1]} | {room[2]}$" for room in rooms])
        print(room_list)
        return f"ROOM_LIST\n{room_list}"
    else:
        print("NO_ROOMS_AVAILABLE")
        return "NO_ROOMS_AVAILABLE"

def handle_join_room(room_id, room_code):
    conn = sqlite3.connect('chatroom.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ChatRooms WHERE room_id = ? AND code = ?", (room_id, room_code))
    room = cursor.fetchone()
    cursor.close()
    conn.close()

    if room:
        return "JOIN_ROOM_SUCCESS"
    else:
        return "JOIN_ROOM_FAILURE"

def handle_send_message(room_id, username, message):
    try:
        conn = sqlite3.connect('chatroom.db')
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM Users WHERE username = ?", (username,))
        user_id = cursor.fetchone()[0]
        cursor.execute("INSERT INTO Messages (room_id, user_id, message_text) VALUES (?, ?, ?)", (room_id, user_id, message))
        conn.commit()
        cursor.close()
        conn.close()
        return "SEND_MESSAGE_SUCCESS"
    except sqlite3.Error as e:
        return f"SEND_MESSAGE_FAILURE: {e}"

def handle_send_image(room_id, username, image_name, encoded_image):
    try:
        conn = sqlite3.connect('chatroom.db')
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM Users WHERE username = ?", (username,))
        user_id = cursor.fetchone()[0]
        cursor.execute("INSERT INTO File (chatroom_id, user_id, filename, file, timestamp) VALUES (?, ?, ?, ?, ?)",(room_id, user_id, image_name, encoded_image, datetime.today()))
        conn.commit()
        cursor.close()
        conn.close()
        return "SEND_IMAGE_SUCCESS"
    except sqlite3.Error as e:
        return f"SEND_IMAGE_FAILURE: {e}"


def broadcast_image(client_socket, room_id, username, encoded_image):
    formatted_image = f"IMAGE_INCOMING {datetime.today()}${username}${encoded_image}"
    print(f"Broadcasting image: {formatted_image}")
    for client in clients_by_room.get(room_id, []):
        try:
            if client != client_socket:
                client.sendall(formatted_image.encode())
        except Exception as e:
            print(f"Error broadcasting image to client: {e}")


def send_verification_code(email, code):

    msg = EmailMessage()
    msg.set_content(f"Your verification code is: {code}")
    msg['Subject'] = 'Your Verification Code'
    msg['From'] = "ChatSec"
    msg['To'] = email

    # Send the message via our own SMTP server.
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login("cf.etudiant@gmail.com", "pdhm sapa cudg lgam")
    server.send_message(msg)
    server.quit()

def get_user_email(username):
    conn = sqlite3.connect('chatroom.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM Users WHERE username = ?", (username,))
    email = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return decrypt(key, email)

def generate_verification_code():
    return str(random.randint(100000, 999999))

# Encryption
# The key for each room is stored in the DB, each room got a different encryption key
def generate_key():
    return get_random_bytes(32)
def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)  # Creating the cipher with the key
    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)  # Encryption
    # Encode ciphertext in base64 for storage or transmission
    return base64.b64encode(ciphertext).decode('utf-8')
def decrypt(key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))  # decode from base 64
    cipher = AES.new(key, AES.MODE_ECB)  # recreating the cipher
    decrypted_data = cipher.decrypt(encrypted_data)  # decrypting
    # Remove padding from decrypted plaintext
    plaintext = unpad(decrypted_data, AES.block_size).decode('utf-8')
    return plaintext
def pad(data, block_size):  # Adding padding to fit the 16 bytes size of blocks for AES
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length]) * padding_length
    return data + padding
key = b'C\x89m\xe9e\x86y#\xb7\xba3\nZ\x0bz\x17\xc3\x1d\xc8\xcaVr\xc3\xd0M\x1d\xb6\xaa\x99\x88\x9fx'
def unpad(data, block_size):  # Unpadding to read the message
    padding_length = data[-1]
    return data[:-padding_length]

# Server Initialization with SSL/TLS
def start_server():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(5)
    print("Server started, waiting for connections...")

    # Wrap the server socket with SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    server_socket = context.wrap_socket(server_socket, server_side=True)

    while True:
        client_socket, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()


if __name__ == "__main__":
    start_server()
