import struct

class Response:
    HEADER_FORMAT = "<BHI" # 1 byte for version, 2 bytes for code, 4 bytes for payload size
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    VERSION = 3

    def __init__(self, code, payload):
        self.version = Response.VERSION
        self.code = code
        self.payload_size = len(payload)
        self.payload = payload

    def pack(self):
        # pack the values of the header
        header = struct.pack(Response.HEADER_FORMAT, self.version, self.code, self.payload_size)
        if isinstance(self.payload, bytes):
            return header + self.payload
        # make sure the payload is a bytes object by encoding it and adding it to the header
        return header + str(self.payload).encode()

    def send(self, connection):
        # pack the response and send it to the client
        connection.sendall(self.pack())
