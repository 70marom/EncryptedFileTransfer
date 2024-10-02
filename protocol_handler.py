from response import Response


def failed_register():
    return Response(1601, b"")

def success_register(client_id):
    return Response(1600, client_id)

def success_login(client_id, aes_key):
    payload = client_id + aes_key
    return Response(1605, payload)

def failed_login(client_id):
    return Response(1606, client_id)

def general_error():
    return Response(1607, b"")

def send_aes_key(client_id, aes_key):
    payload = client_id + aes_key
    return Response(1602, payload)

def send_file_crc(client_id, content_size, file_name, crc):
    payload = client_id + content_size.to_bytes(4, 'little') + file_name.encode() + crc.to_bytes(4, 'little')
    return Response(1603, payload)

def send_final_confirmation(client_id):
    return Response(1604, client_id)
