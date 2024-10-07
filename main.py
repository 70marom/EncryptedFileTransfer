import os.path
import socket
import threading
from client import Client
from database import Database


def session(conn, addr, database):
    print(f"Client connected from {addr[0]}")
    client = Client(conn, addr[0], database) # Create a new client object
    client.get_requests() # begin the session by getting requests from the client
    conn.close()
    print(f"Client disconnected from {addr[0]}")


def get_port() -> int:
    if not os.path.isfile('port.info'): # if port.info does not exist, use default port 1256
        print("Warning: port.info not found. Using default port 1256.")
        return 1256
    with open('port.info', 'r') as file:
        port = file.read()
        try:
            port = int(port) # convert port to integer
        except ValueError: # if port.info is not a valid port number, use default port 1256
            print("Warning: port.info is not a valid port number. Using default port 1256.")
            return 1256
        return port


def main():
    port = get_port()
    database = Database() # create or open the database file
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            s.listen()
            print(f"Server is listening on port {port}")
            while True:
                # for each client that connects, create a new thread to handle the session
                conn, addr = s.accept()
                client_thread = threading.Thread(target=session, args=(conn, addr, database))
                client_thread.start()
        except Exception:
            print("Error: failed to start server! Check if the port is already in use.")


if __name__ == '__main__':
    main()
