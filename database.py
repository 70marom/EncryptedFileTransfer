import sqlite3
import threading

class Database:
    def __init__(self):
        self.connection = sqlite3.connect('database.db', check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.lock = threading.Lock()
        self.create_clients_table()
        self.create_files_table()

    def create_clients_table(self):
        with self.lock:
            self.cursor.execute('CREATE TABLE IF NOT EXISTS ' +
                                'clients (ID BINARY(16) PRIMARY KEY, ' +
                                'Name VARCHAR(255), ' +
                                'PublicKey CHAR(160), ' +
                                'LastSeen DATETIME, ' +
                                'AESKey CHAR(32))')
            self.connection.commit()

    def create_files_table(self):
        with self.lock:
            self.cursor.execute('CREATE TABLE IF NOT EXISTS ' +
                                'files (ID BINARY(16), ' +
                                'FileName VARCHAR(255) PRIMARY KEY, ' +
                                'PathName VARCHAR(255), ' +
                                'Verified BOOLEAN)')
            self.connection.commit()

    def close(self):
        with self.lock:
            if self.cursor:
                self.cursor.close()
            if self.connection:
                self.connection.close()

    def client_exists(self, name):
        with self.lock:
            try:
                self.cursor.execute('SELECT Name FROM clients WHERE Name = ?', (name,))
                return self.cursor.fetchone() is not None
            except sqlite3.Error:
                print("Error: failed to check in database if client exists.")
                return None

    def register_client(self, client_id, name):
        with self.lock:
            try:
                self.cursor.execute('INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey) ' +
                                    'VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)', (client_id, name, None, None))
                self.connection.commit()
                return True
            except sqlite3.Error:
                print("Error: failed to register client in database.")
                return False

    def client_exists_by_id(self, client_id, name):
        with self.lock:
            try:
                self.cursor.execute('SELECT Name FROM clients WHERE ID = ?', (client_id,))
                result = self.cursor.fetchone()
                return result is not None and result[0] == name
            except sqlite3.Error:
                print("Error: failed to check in database if client exists by ID.")
                return None

    def get_aes_key(self, client_id):
        with self.lock:
            try:
                self.cursor.execute('SELECT AESKey FROM clients WHERE ID = ?', (client_id,))
                return self.cursor.fetchone()[0]
            except sqlite3.Error:
                print("Error: failed to get AES key from database.")
                return None

    def get_public_key(self, client_id):
        with self.lock:
            try:
                self.cursor.execute('SELECT PublicKey FROM clients WHERE ID = ?', (client_id,))
                return self.cursor.fetchone()[0]
            except sqlite3.Error:
                print("Error: failed to get public key from database.")
                return None

    def add_public_key(self, client_id, public_key):
        with self.lock:
            try:
                self.cursor.execute('UPDATE clients SET PublicKey = ? WHERE ID = ?', (public_key, client_id))
                self.connection.commit()
                return True
            except sqlite3.Error:
                print("Error: failed to add public key to database.")
                return False

    def add_aes_key(self, client_id, aes_key):
        with self.lock:
            try:
                self.cursor.execute('UPDATE clients SET AESKey = ? WHERE ID = ?', (aes_key, client_id))
                self.connection.commit()
                return True
            except sqlite3.Error:
                print("Error: failed to add AES key to database.")
                return False

    def update_last_seen(self, client_id):
        with self.lock:
            try:
                self.cursor.execute('UPDATE clients SET LastSeen = CURRENT_TIMESTAMP WHERE ID = ?', (client_id,))
                self.connection.commit()
                return True
            except sqlite3.Error:
                print("Error: failed to update last seen of a client in database.")
                return False

    def save_file(self, client_id, file_name, file_path, is_verified=True):
        with self.lock:
            try:
                self.cursor.execute('INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)',
                                    (client_id, file_name, file_path, is_verified))
                self.connection.commit()
                return True
            except sqlite3.Error:
                print("Error: failed to save file's information in database.")
                return False
