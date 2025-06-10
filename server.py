import sys
import socket
import threading
import struct
import json
import time

MAX_CONNECTIONS = 2

client_sockets = []
# Stores {username: {ik_public, ek_public}}
client_keys = {}
key_mutex = threading.Lock()
broadcast_mutex = threading.Lock()

'''
    Purpose:
        Receive all the incoming data by reading n length long bytes.
    
    Input:
        socket in socket form
        length of the data
    Output:
        data packet
'''
def recv_all(sock:socket.socket, length):
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

'''
    Purpose:
        receiving JSON form data from TCP packet
    
    Input:
        socket 
    Output:
        JSON form of packet
'''
def recv_json(sock:socket.socket):
    try:
        length_bytes = recv_all(sock, 4)
        if not length_bytes:
            return None
        length = struct.unpack(">I", length_bytes)[0]
        message_bytes = recv_all(sock, length)
        if not message_bytes:
            return None
        return json.loads(message_bytes.decode('utf-8'))
    except Exception as e:
        print(f"[ERR] Failed to receive JSON: {e}")
        return None

'''
    Purpose:
        sending JSON data to another socket.
    
    Implementation:
        First 4 bytes represents data size. This is allows the exact size of data to read for each message.
        First 4 bytes can represent upto 2**(32) - 1 integers.

    Input: 
        Receiving socket
        JSON data
    Output:
        None
'''
def send_json(sock:socket.socket, data):
    try:
        json_bytes = json.dumps(data).encode('utf-8')
        length = len(json_bytes)
        sock.sendall(struct.pack(">I", length))
        sock.sendall(json_bytes)
    except Exception as e:
        print(f"[ERR] Failed to send JSON: {e}")

'''
    Purpose:
        Each thread will handle each client. It will store and send X3DH data whenever there is get request.
    
    Input:
        socket
'''
def handle_client(client_socket:socket.socket):
    peer = client_socket.getpeername()
    username = None
    try:
        while 1:
            data = recv_json(client_socket)
            if not data:
                break

            if data["type"] == "X3DH_init":
                username = data["username"]
                with key_mutex:
                    client_keys[username] = {
                        "ik_public": data["ik_public"],
                        "ek_public": data["ek_public"]
                    }
                print(f"[X3DH] Stored keys for {username}")
                print(f"current key: {client_keys}")

            elif data["type"] == "X3DH_get":
                requester = data["requester"]
                peer_found = False
                while not peer_found:
                    with key_mutex:
                        for user, keys in client_keys.items():
                            if user != requester:
                                send_json(client_socket, {
                                    "type": "X3DH_peer",
                                    "username": user,
                                    "ik_public": keys["ik_public"],
                                    "ek_public": keys["ek_public"]
                                })
                                peer_found = True
                                break
                    if not peer_found:
                        time.sleep(0.5)  # wait and retry until a peer is available

            elif data["type"] == "chat":
                with broadcast_mutex:
                    for sock in client_sockets:
                        if sock != client_socket:
                            send_json(sock, data)
                            print(f"{data}")

    except Exception as e:
        print(f"[ERR] Error handling {peer}: {e}")
    finally:
        with broadcast_mutex:
            if client_socket in client_sockets:
                client_sockets.remove(client_socket)
        client_socket.close()
        print(f"[INFO] Client {peer} disconnected.")

'''
    Main function

    Usage:
        python server.py <IP Address> <Port #>
'''
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python server.py <IP Address> <port>")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)
    print(f"[INFO] Server listening on {HOST}:{PORT}")

    try:
        while True:
            if len(client_sockets) < MAX_CONNECTIONS:
                client_socket, addr = server_socket.accept()
                print(f"[INFO] Connection from {addr}")
                with broadcast_mutex:
                    client_sockets.append(client_socket)
                threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down server.")
    finally:
        server_socket.close()