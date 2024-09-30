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
