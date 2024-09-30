import struct

class Response:
    HEADER_FORMAT = "<BHI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, code, payload):
        self.version = 3
        self.code = code
        self.payload_size = len(payload)
        self.payload = payload

    def pack(self):
        header = struct.pack(Response.HEADER_FORMAT, self.version, self.code, self.payload_size)
        if isinstance(self.payload, bytes):
            return header + self.payload
        return header + str(self.payload).encode()

    def send(self, connection):
        connection.sendall(self.pack())
