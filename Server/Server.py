import socket
import threading
import struct
import uuid
import os
import base64

from cksum import cksum
from Database import DB
import criptUtil
"""
Author: Guy Pridan
Description: This Python script serves as a server that handles client requests concurrently using separate threads.

This server implementation allows multiple clients to connect and interact with the server simultaneously.
It utilizes a multi-threaded approach to ensure responsiveness to multiple client requests.
Each connected client is assigned to a separate thread, allowing for concurrent execution of client interactions.

The main components and functionalities of this code include:
1. Server Socket Setup: The code sets up a socket to listen for incoming client connections on a specified port.

2. Thread Management: For each incoming client connection, a new thread is spawned to handle the client's requests independently.

3. Request Processing: The code includes logic to process client requests, such as sending and receiving data, 
   in accordance with the given protocol - https://drive.google.com/file/d/1F6iSWqT7q79e3AF59GjbiIudkrhdSqwo/view?usp=sharing
   
4. Exception Handling: Proper exception handling is implemented to ensure the server remains stable and can handle unexpected errors.
"""

server_v = 3

# format
packet_size = 1024
cid_size = 16
name_size = 255
rsa_key_size = 160
req_header_size = 23
file_header_size = 255 + 4  # file name(255b) and content size(4b)
crc_header_size = 16 + 4 + 255 + 4  # cid(16), content size(4b), file name(255b), cksum(4b)
req_header_format = "<16sBHI"

# requests codes
req_register = 1025
req_send_pub_key = 1026
req_reconnect = 1027
req_send_file = 1028
req_valid_crc = 1029
req_invalid_crc = 1030
req_final_invalid_crc = 1031

# response codes
res_reg_success = 2100
res_reg_failure = 2101
res_send_aes = 2102
res_send_crc = 2103
res_confirmed_msg = 2104
res_reconnect_success = 2105
res_reconnect_failed = 2106
res_general_error = 2107


def general_error_response():
    return struct.pack("<BHI", server_v, res_general_error, 0)


def confirm_msg(cid: bytes) -> bytes:
    return struct.pack(f"<BHI{cid_size}s",
                       server_v,
                       res_confirmed_msg,
                       cid_size,
                       cid)


def pretify_byte_count(count: int) -> str:
    ret = ""
    scale = 0
    while count > 1024 and scale < 4:
        scale += 1
        count //= 1024
    scale_def = ['b', 'kb', 'mg', 'gb', 'tb']
    return str(count) + scale_def[scale]


class Server:
    host = "127.0.0.1"
    default_port = 1357
    mutex = threading.Lock()

    def __init__(self):
        # read port num from port.info
        try:
            with open("port.info", "r") as f:
                self.port = int(f.readline())
        except FileNotFoundError:
            self.port = self.default_port

        # load database to ram memory
        self.db = DB()

        # create socket for server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen()

        # create backup folder:
        if not os.path.exists("backup"):
            os.mkdir("backup")

        # accept clients and create threads accordingly
        self.lock_print(self.host + ":" + str(self.port) + " - Waiting for incoming connections...")
        while True:
            client_socket, client_addr = self.sock.accept()
            self.lock_print(f"Accepted connection from {client_addr}")

            # Start a new thread to handle the client
            client_handler = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_handler.start()

    def handle_client(self, c_sock: socket):
        data = c_sock.recv(packet_size)
        cid, c_version, req_code, payload_size = struct.unpack(req_header_format, data[:req_header_size])

        # generate response according to request code
        if req_code == req_register:
            response = self.reg(payload_size, data)

        elif req_code in [req_send_pub_key, req_reconnect]:
            response = self.pack_aes(req_code, cid, payload_size, data)

        elif req_code == req_send_file:
            response = self.recv_file(c_sock, cid, data)

        elif req_code == req_valid_crc or req_code == req_final_invalid_crc:
            self.lock_print(f"end communication with user 0x{cid.hex()}")
            response = confirm_msg(cid)

        elif req_code == req_invalid_crc:
            self.delete_file(cid, data)
            return

        else:
            # unrecognized request code
            response = general_error_response()

        c_sock.send(response)

    def reg(self, payload_size: int, data: bytes) -> bytes:

        # register new user to clients db
        name_bytes, = struct.unpack(f"<{payload_size}s", data[req_header_size:req_header_size + payload_size])
        name = name_bytes.decode('utf-8').rstrip('\x00')

        if self.valid_name(name):
            cid = uuid.uuid4().bytes
            self.db.add_client(cid, name)
            response = struct.pack(f"<BHI{cid_size}s", server_v, res_reg_success, cid_size, cid)
            self.lock_print(f"{name} successfully registered with id 0x{cid.hex()}")

        else:
            self.lock_print(f"username '{name}' is already taken. registry failed")
            response = struct.pack("<BHI", server_v, res_reg_failure, 0)

        return response

    def pack_aes(self, req_code: int, cid: bytes, payload_size: int, data: bytes):

        self.lock_print("generating and sending an encrypted aes key to user 0x" + cid.hex())

        if req_code == req_send_pub_key:

            # unpack rsa_data
            rsa_data, = struct.unpack(f"<{rsa_key_size}s",
                                      data[req_header_size + name_size:req_header_size + payload_size])
            res_code = res_send_aes
            aes_key = criptUtil.generate_aes().IV

            # update db
            self.db.insert_cript_keys(cid, rsa_data, aes_key)

        else:
            # get rsa_data from db
            rsa_data, _ = self.db.get_keys(cid)

            # generate new aes key
            aes_key = criptUtil.generate_aes().IV
            self.db.insert_aes(cid, aes_key)
            res_code = res_reconnect_success

        enc = criptUtil.encrypt_aes(aes_key, rsa_data)

        # generate response
        payload_size = cid_size + len(enc)
        response = struct.pack(f"<BHI{cid_size}s{len(enc)}s",
                               server_v,
                               res_code,
                               payload_size,
                               cid,
                               enc)

        return response

    def recv_file(self, c_sock: socket, cid: bytes, data: bytes):
        file_size, file_name_bytes = struct.unpack(f"<I{name_size}s",
                                                   data[req_header_size:req_header_size + file_header_size])
        file_name = file_name_bytes.decode('utf-8').rstrip('\x00')
        rem_file_size = file_size
        self.lock_print(
            f"waiting for encrypted file data from user 0x{cid.hex()}\n{file_name} ({pretify_byte_count(file_size)})"
        )

        # receive data
        encrypted_data = bytearray()
        while rem_file_size > 0:
            bytes_recv = c_sock.recv(packet_size)
            encrypted_data.extend(bytes_recv)
            rem_file_size -= packet_size

        # decrypt data
        _, aes_key = self.db.get_keys(cid)
        decrypted_data = criptUtil.decrypt(encrypted_data[:file_size], aes_key)

        # create file
        user_folder_name = base64.b64encode(cid.hex().encode("ascii")).decode('ascii')
        dir_path = os.path.join("backup", user_folder_name)
        f_path = os.path.join(dir_path, str(file_name))
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

        with open(f_path, 'wb') as f:
            f.write(decrypted_data)

        # check crc
        crc = cksum(f_path)

        # add file info to db
        self.db.add_file(cid, file_name, f_path)

        # return response
        return struct.pack(f"<BHI{cid_size}sI{name_size}sI",
                           server_v,
                           res_send_crc,
                           crc_header_size,
                           cid,
                           file_size,
                           file_name_bytes,
                           crc)

    def delete_file(self, cid: bytes, data: bytes):
        file_name_bytes, = struct.unpack(f"<{name_size}s", data[req_header_size:req_header_size + name_size])
        file_name = file_name_bytes.decode('utf-8').rstrip('\x00')

        self.lock_print(f"Got a wrong checksum result for {file_name}, deleting file.")

        user_folder_name = base64.b64encode(cid.hex().encode("ascii")).decode('ascii')
        dir_path = os.path.join("backup", user_folder_name)
        f_path = os.path.join(dir_path, str(file_name))

        try:
            os.remove(f_path)
        except:
            self.lock_print(f"failed while trying to delete {f_path}")

        self.db.remove_file(cid, file_name)

    def valid_name(self, name: str) -> bool:

        # TODO: check for possible SQL injection

        matches = self.db.get_table("clients", "WHERE name=?", (name,))
        return not matches

    def lock_print(self, param: any) -> None:
        self.mutex.acquire()
        try:
            print(param)
        finally:
            self.mutex.release()
