import socket
import ssl
import threading
import time
import tkinter as tk
from datetime import datetime,timedelta
from tkinter import scrolledtext, messagebox, Listbox

message_by_room = {}
class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chatroom")

        # Styles
        self.heading_font = ("Helvetica", 16, "bold")
        self.label_font = ("Helvetica", 12)
        self.button_style = {"font": ("Helvetica", 12), "padx": 10, "pady": 5}

        # Data
        self.username = None
        self.password = None
        self.selected_room = None
        self.listening = True
        self.room_list = {"Room A": "passwordA", "Room B": "passwordB",
                          "Room C": "passwordC"}  # Example rooms and passwords

        # Socket setup with SSL
        self.server_address = ('localhost', 65432)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap the socket with SSL
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Only for development; do not use in production
        self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.server_address[0])

        self.ssl_sock.connect(self.server_address)

        # Start a thread to listen for messages from the server
        # Create initial page
        self.create_initial_page()

    def listen_for_messages(self,name):
        if self.listening:
            try:
                #Ici cela attend et capte le premier message recu du servuer => probleme
                #self.ssl_sock.setblocking(0)
                message = self.ssl_sock.recv(1024).decode().strip()
                print(f"Received message: {message}")
                if message.startswith("MESSAGE_INCOMING"):
                    message = message.replace("MESSAGE_INCOMING", "").strip()
                    timestamp,username,message = message.split("$")
                    self.display_message(timestamp,username,message)
            except Exception as e:
                print(f"Error receiving message: {e}")
        #self.ssl_sock.setblocking(1)
        return

    def create_initial_page(self):
        self.clear_window()

        tk.Label(self.root, text="Welcome to Secure Chatroom", font=self.heading_font).pack(pady=20)

        tk.Button(self.root, text="Login", command=self.show_login_page, **self.button_style).pack(pady=(0, 10))
        tk.Button(self.root, text="Register", command=self.show_register_page, **self.button_style).pack(pady=10)

    def show_login_page(self):
        self.clear_window()

        tk.Label(self.root, text="Login to Secure Chatroom", font=self.heading_font).pack(pady=20)

        tk.Label(self.root, text="Email:", font=self.label_font).pack(pady=5)
        self.email_entry = tk.Entry(self.root)
        self.email_entry.pack(pady=5)

        tk.Label(self.root, text="Username:", font=self.label_font).pack(pady=5)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Password:", font=self.label_font).pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.root, text="Login", command=self.login, **self.button_style).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.create_initial_page, **self.button_style).pack(pady=10)

    def show_register_page(self):
        self.clear_window()
        #printsijijithji
        tk.Label(self.root, text="Register for Secure Chatroom", font=self.heading_font).pack(pady=20)

        tk.Label(self.root, text="Email:", font=self.label_font).pack(pady=5)
        self.email_entry = tk.Entry(self.root)
        self.email_entry.pack(pady=5)

        tk.Label(self.root, text="Username:", font=self.label_font).pack(pady=5)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Password:", font=self.label_font).pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.root, text="Register", command=self.register, **self.button_style).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.create_initial_page, **self.button_style).pack(pady=10)

    def login(self):
        self.email = self.email_entry.get().strip()
        self.username = self.username_entry.get().strip()
        self.password = self.password_entry.get().strip()

        if not self.email or not self.username or not self.password:
            messagebox.showerror("Error", "Email, Username, and Password are required!")
            return

        if self.authenticate_user(self.username, self.password):
            self.show_2fa_window("login")
        else:
            messagebox.showerror("Error", "Invalid Email, Username, or Password")


    def show_2fa_window(self, action):
        self.clear_window()
        tk.Label(self.root, text="We sent to you a mail at "+self.email+"\n Enter 2FA Code", font=self.heading_font).pack(pady=20)

        self.two_fa_entry = tk.Entry(self.root)
        self.two_fa_entry.pack(pady=5)

        tk.Button(self.root, text="Submit", command=lambda: self.check_2fa(action), **self.button_style).pack(pady=10)

    def check_2fa(self, action):
        code = self.two_fa_entry.get().strip()
        if code == "0000":
            if action == "login":
                self.show_room_selection_page()
            elif action == "register":
                self.show_room_selection_page()
        else:
            messagebox.showerror("Error", "Invalid 2FA Code")










    def authenticate_user(self, username, password):
        # Simulated authentication logic (replace with actual logic)

        if username and password:
            self.send_request(f"LOGIN {username} {password}")

            response = self.receive_response()
            print(f'response : {response}')
            if response == "LOGIN_SUCCESS":
                print('success')
                return True
                # Proceed to the next step (e.g., join room)
            else:
                print("failed")
        else:
            print('no username or pass')

        # For demo purposes, always return True
        return False

    def send_request(self, request):
        """Sends a request to the server."""
        try:
            self.listening = False
            self.ssl_sock.setblocking(1)
            print(f"Sending request: {request} : listening : {self.listening}")
            self.ssl_sock.sendall(request.encode())
        except Exception as e:
            print(f"Error sending request: {e}")

    def receive_response(self):
        """Receives a response from the server."""
        try:
            response = self.ssl_sock.recv(4096).decode().strip()
            print(f"Received response: {response}")
            self.listening = True

            #threading.Thread(target=self.listen_for_messages, args=(1,), daemon=True).start()
            return response
        except Exception as e:
            print(f"Error receiving response: {e}")
            return ""

    def register(self):
        # self.email = self.email_entry.get().strip()
        self.username = self.username_entry.get().strip()
        self.password = self.password_entry.get().strip()

        if not self.username or not self.password:
            messagebox.showerror("Error", "Email, Username, and Password are required!")
            return

        self.send_request(f"REGISTER {self.username} {self.password}")
        response = self.receive_response()
        if response == "REGISTER_SUCCESS":
            messagebox.showinfo("Success", f"Account '{self.username}' created successfully!")
            self.show_2fa_window("register")
        else:
            messagebox.showerror("Error", f"Account '{self.username}' not created")

    def update_room_list(self):
        self.send_request("LIST_ROOMS")
        response = self.receive_response()
        if response.startswith("ROOM_LIST"):
            # Remove 'ROOM_LIST' from the response and split the rooms
            response = response.replace("ROOM_LIST", "").strip()
            rooms = response.split("$")
            print(f'rooms : {rooms}')
            self.room_list = {room: "" for room in rooms}
        else:
            self.room_list = {}

    def show_room_selection_page(self):
        self.update_room_list()
        self.clear_window()

        tk.Label(self.root, text="Select Room", font=self.heading_font).pack(pady=20)

        # Create listbox for available rooms
        self.room_listbox = Listbox(self.root, selectmode=tk.SINGLE, font=self.label_font)
        self.room_listbox.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        for room in self.room_list:
            self.room_listbox.insert(tk.END, room)

        # Entry for room password
        tk.Label(self.root, text="Room Password:", font=self.label_font).pack(pady=5)
        self.room_password_entry = tk.Entry(self.root, show="*", font=self.label_font)
        self.room_password_entry.pack(pady=5)

        tk.Button(self.root, text="Join", command=self.join_room, **self.button_style).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.create_initial_page, **self.button_style).pack(pady=10)

    def join_room(self):
        index = self.room_listbox.curselection()
        if index:
            selected_room = self.room_listbox.get(index)
            self.selected_room = selected_room
            if selected_room in self.room_list:
                expected_password = self.room_list[selected_room]
                entered_password = self.room_password_entry.get().strip()
                self.send_request(f"JOIN_ROOM {selected_room[0]} {entered_password}")
                response = self.receive_response()
                print(f'response : {response}')
                if response == "JOIN_ROOM_SUCCESS":
                    self.selected_room = selected_room
                    messagebox.showinfo("Joined Room", f"You joined room: {self.selected_room}")
                    self.create_chatroom()
                    self.retrieve_room_history()
                    #Create a thread that update history every 2 seconds :
                    threading.Thread(target=self.wrapper_history, args=(1,), daemon=True).start()
                    
                else:
                    messagebox.showerror("Error", "Incorrect Room Password")

    def wrapper_history(self,name):
        while True:
            self.retrieve_room_history()
            time.sleep(0.5)

    def retrieve_room_history(self):
        self.send_request(f"LIST_MESSAGES {self.selected_room[0]}")
        if self.selected_room[0] not in message_by_room:
            message_by_room[self.selected_room[0]] = []
        response = self.receive_response()
        if response.startswith("MESSAGE_LIST"):
            # Remove 'MESSAGES' from the response and split the messages
            response = response.replace("MESSAGE_LIST", "").strip()
            messages = response.split("$")
            print(f'messages : {messages}')
            for message in messages:
                if not message or len(message) < 3:
                    continue
                print(f'message : {message}')
                if message not in message_by_room[self.selected_room[0]]:
                    message_by_room[self.selected_room[0]].append(message)
                    timestamp, sender, message_text = message.split("%ù%")
                    self.receive_message(timestamp, sender, message_text)
                else : continue
        else:
            print("No messages found")

    def create_chatroom(self):
        self.clear_window()

        # Label to show current username and room
        self.username_label = tk.Label(self.root, text=f"Logged in as: {self.username} | Room: {self.selected_room}",
                                       font=self.label_font)
        self.username_label.pack(pady=10)

        # Create chat display area
        self.chat_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=self.label_font, state='disabled')
        self.chat_display.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        # Create input area for messages
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(fill=tk.X, padx=20, pady=(0, 10))  # Adjusted padding for bottom space

        self.input_text = tk.Entry(self.input_frame, font=self.label_font)
        self.input_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.input_text.bind("<Return>", self.send_message)

        tk.Button(self.input_frame, text="Send", command=self.send_message, **self.button_style).pack(side=tk.RIGHT)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def send_message(self, event=None):
        message = self.input_text.get()
        if message:
            self.input_text.delete(0, tk.END)
            # Here you would add the code to send the message to the server
            # Example: self.client_socket.sendall(message.encode())
            self.send_request(f"SEND_MESSAGE {self.selected_room[0]} {self.username} {message}")
            response = self.receive_response()
            if response == "SEND_MESSAGE_SUCCESS":
                print("Message sent successfully")
            else:
                print("Failed to send message")

    def receive_message(self, timestamp, sender, message):
        self.display_message(timestamp, sender, message)

    def display_message(self, timestamp, sender, message):
        self.chat_display.config(state='normal')
        temp = str(timestamp)[1:-1]
        self.chat_display.insert(tk.END, f"[{temp}] {sender}: {message}\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)


# tkinter end
if True:
    root = tk.Tk()
    client = SecureChatClient(root)
    root.geometry("600x400")
    root.mainloop()
    # initialize_database()
