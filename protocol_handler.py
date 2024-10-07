from response import Response
from codes import ResponseCode

def failed_register():
    return Response(ResponseCode.FAILED_REGISTRATION, b"")

def success_register(client_id):
    return Response(ResponseCode.SUCCESS_REGISTRATION, client_id)

def success_login(client_id, aes_key):
    payload = client_id + aes_key
    return Response(ResponseCode.SUCCESS_LOGIN, payload)

def failed_login(client_id):
    return Response(ResponseCode.FAILED_LOGIN, client_id)

def general_error():
    return Response(ResponseCode.GENERAL_ERROR, b"")

def send_aes_key(client_id, aes_key):
    payload = client_id + aes_key
    return Response(ResponseCode.SEND_AES_KEY, payload)

def send_file_crc(client_id, content_size, file_name, crc):
    # convert content_size and crc to bytes in little endian format
    payload = client_id + content_size.to_bytes(4, 'little') + file_name.encode() + crc.to_bytes(4, 'little')
    return Response(ResponseCode.SEND_FILE_CRC, payload)

def send_final_confirmation(client_id):
    return Response(ResponseCode.SEND_FINAL_CONFIRMATION, client_id)
