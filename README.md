Server for the Encrypted File Transfer. The server is responsible for:
* Handling client connections using threads
* Managing registered users in a database using SQLite
* Decode requests according to a custom protocol over TCP
* Generates an AES-CBC key and encrypts it using the client's RSA public key
* Decrypting files using the AES key
* Verifying file integrity using CRC checksums
* Stores the decrypted file in the memory

Uses PyCryptodome for encryption operations

Stores user data and file information in a database

Maintains a local directory for received files

The server reads its port number from a port.info file and listens for client requests indefinitely.
