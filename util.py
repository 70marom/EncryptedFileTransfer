import hashlib
import uuid


def string_to_uuid(string: str) -> str:
    hash_value = hashlib.sha256(string.encode('utf-8')).digest()
    uuid_bytes = hash_value[:16]
    uuid_obj = uuid.UUID(bytes=uuid_bytes)
    return uuid_obj.hex
