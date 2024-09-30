import os.path
import socket
import threading
from client import Client
from database import Database


def session(conn, addr, database):
    print(f"Client connected from {addr[0]}")
    client = Client(conn, addr[0], database)
    client.get_requests()
    conn.close()
    print(f"Client disconnected from {addr[0]}")


def get_port() -> int:
    if not os.path.isfile('port.info'):
        print("Warning: port.info not found. Using default port 1256.")
        return 1256
    with open('port.info', 'r') as file:
        port = file.read()
        try:
            port = int(port)
        except ValueError:
            print("Warning: port.info is not a valid port number. Using default port 1256.")
            return 1256
        return port


def main():
    port = get_port()
    database = Database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            s.listen()
            print(f"Server is listening on port {port}")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=session, args=(conn, addr, database))
                client_thread.start()
        except Exception:
            print("Error: failed to start server! Check if the port is already in use.")


if __name__ == '__main__':
    main()
