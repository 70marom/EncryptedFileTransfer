import hashlib
import uuid

def string_to_uuid(string):
    hash_value = hashlib.sha256(string.encode('utf-8')).digest() # hash the string
    uuid_bytes = hash_value[:16] # take the first 16 bytes of the hash, which is the size of the client ID
    uuid_obj = uuid.UUID(bytes=uuid_bytes) # create a UUID object from the 16 bytes
    return uuid_obj.hex # return the UUID object as a hex string
