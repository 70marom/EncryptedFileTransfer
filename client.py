import os.path
import struct
from Crypto.Random import get_random_bytes
from protocol_handler import failed_register, success_register, success_login, failed_login, send_aes_key
from util import string_to_uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

class Client:
    def __init__(self, connection, address, database):
        self.connection = connection
        self.address = address
        self.database = database
        self.client_id = None
        self.aes_key = None
        self.name = None
        self.received_packets = 0

    def get_requests(self):
        header = self.connection.recv(23)
        if not header:
            return None
        self.client_id, version, code, payload_size = struct.unpack('<16sBHI', header)
        payload = self.connection.recv(payload_size)
        match code:
            case 825:
                self.handle_register(payload)
            case 826:
                self.handle_public_key(payload)
            case 827:
                self.handle_login(payload)
            case 828:
                self.handle_save_file(payload)
            case default:
                print(f"Received unknown request code {code} from {self.address}")
                failed_register().send(self.connection)

    def handle_register(self, payload):
        if self.database.client_exists(payload):
            print(f"{self.address} tried to register with the name {payload.decode()[:-1]}, but it's already taken.")
            failed_register().send(self.connection)
        else:
            self.client_id = bytes.fromhex(string_to_uuid(payload.decode()))
            self.database.register_client(self.client_id, payload.decode())
            print(f"{self.address} registered with the name {payload.decode()[:-1]}")
            self.name = payload.decode()[:-1]
            success_register(self.client_id).send(self.connection)
            self.get_requests()

    def handle_login(self, payload):
        if self.database.client_exists_by_id(self.client_id, payload.decode()):
            print(f"{self.address} logged in with the name {payload.decode()[:-1]}")
            self.name = payload.decode()[:-1]
            self.generate_aes_key()
            success_login(self.client_id, self.database.get_aes_key(self.client_id)).send(self.connection)
            print(f"Sent AES key to {self.address}.")
            self.get_requests()
        else:
            print(f"{self.address} tried to log in with the name {payload.decode()[:-1]}, but it's not registered " +
                  "or its UUID is not valid.")
            failed_login(self.client_id).send(self.connection)

    def handle_public_key(self, payload):
        public_key = payload[255:]
        self.database.add_public_key(self.client_id, public_key)
        print(f"{self.address} sent its public key.")
        self.generate_aes_key()
        send_aes_key(self.client_id, self.database.get_aes_key(self.client_id)).send(self.connection)
        print(f"Sent AES key to {self.address}.")

    def generate_aes_key(self):
        public_key = self.database.get_public_key(self.client_id)
        public_key = RSA.importKey(public_key)
        aes_key = get_random_bytes(32)
        self.aes_key = aes_key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        self.database.add_aes_key(self.client_id, encrypted_aes_key)
        print(f"Generated a new AES key for {self.address} and encrypted it with the client's public key.")


    def handle_save_file(self, payload):
        content_size, decrypted_size, packet_number, total_packets, file_name = struct.unpack("<IIHH255s", payload[:267])
        file_name = file_name.decode().strip('\x00')
        file_path = os.path.join(self.name, file_name)
        encrypted_data = payload[267:267 + 1024]

        if not os.path.exists(self.name):
            os.makedirs(self.name)
            print(f"Created a directory for {self.name}.")

        if self.received_packets == 0:
            print(f"Receiving file {file_name} from {self.address}, expecting {total_packets} packets.")

        decrypted_data = self.decrypt_data(encrypted_data).rstrip(b'\x00')

        if os.path.exists(file_path):
            os.remove(file_path)

        with open(file_path, 'ab') as file:
            file.write(decrypted_data)
            print(f"Received packet {packet_number} of {file_name} from {self.address}.")

        self.received_packets += 1

        if self.received_packets == total_packets:
            print(f"Received all packets for {file_name} from {self.address}.")

    def decrypt_data(self, data):
        iv = b"\x00" * 16
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)
