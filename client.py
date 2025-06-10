import socket, sys, threading
import json
import struct

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout


from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import os
import base64

# Init terminal logging
session = PromptSession()

# Global variable
send_chain_key = None
peer_ek_public = None
ek_private = None
send_root_key = None
recv_root_key = None
current_peer_ek = None

'''
    Cryptography functions
'''
# Serialize the keys into bytes (base64 encoding)
def serialize_key(public_key:X25519PublicKey):
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()

# Deserialize the base64 public key into X25519PublicKey format
def deserialize_key(public_key:base64.b64encode):
    key_bytes = base64.b64decode(public_key)
    return X25519PublicKey.from_public_bytes(key_bytes)


# Generate the X3DH private key and public secret key
# Can be identity key and epheromic key
def generate_X3DH_keypair():
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()

# Generate the shared key using private key and other client's public key
def compute_shared_key(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey):
    return private_key.exchange(peer_public_key)

# Takes shared secret key and prev root key to derive new root key and chain key
# Purpose: KDF root key is used whenever there is new message flow direction
def kdf_root_key(shared_secret_key, prev_root_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=prev_root_key,
        info=b"DoubleRatchetRootKey"
    )
    derived = hkdf.derive(shared_secret_key)
    new_root_key = derived[:32]
    new_chain_key = derived[32:]
    return new_root_key, new_chain_key

# Take the previous chain key and make another chain key and message key
# Purpose: KDF chain key is used when we still have the same sending direction
def kdf_chain_key(chain_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"DoubleRatchetChainKey",
    )
    derived = hkdf.derive(chain_key)
    next_chain_key = derived[:32]
    message_key = derived[32:]
    return next_chain_key, message_key

# Encrypts the plaintext using message key. 
# generates ciphertext and nonce (one time use key)
def encrypt_message(message_key, plaintext):
    aead = ChaCha20Poly1305(message_key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

# takes the message key, nonce to convert the ciphertext to plaintext
def decrypt_message(message_key, nonce, ciphertext):
    aead = ChaCha20Poly1305(message_key)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

'''
    sending_messages
    Input:
    1. socket
    2. data in json format
'''
def send_json(sock:socket.socket, data:json):
    json_bytes = json.dumps(data).encode('utf-8')
    # TODO encrypt here
    length = len(json_bytes)
    # 4-byte big endian length (Max size of (2**32)-1 bits)
    sock.sendall(struct.pack(">I", length))
    # Then send all the json data
    sock.sendall(json_bytes)

'''
    Receiving n amount of message length 
'''
def recv_json(sock):
    # Step 1: Receive 4 bytes for the length
    length_bytes = recv_all(sock, 4)
    if not length_bytes:
        return None

    length = struct.unpack(">I", length_bytes)[0]

    # Step 2: Receive the actual message
    message_bytes = recv_all(sock, length)
    if not message_bytes:
        return None

    return json.loads(message_bytes.decode('utf-8'))

def recv_all(sock, length):
    """Ensure we receive 'length' bytes total."""
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

'''
    Continuous receiving message function.
    This is the main function for the thread.
'''
def recv_messages(client_socket:socket.socket):
    global ek_private, peer_ek_public
    recv_chain_key = None

    while True:
        try:
            # Read message
            encrypted_msg = recv_json(client_socket)
            if not encrypted_msg:
                break

            # Deserialize fields
            new_peer_ek_public = deserialize_key(encrypted_msg["ek_public"])
            nonce = base64.b64decode(encrypted_msg["nonce"])
            ciphertext = base64.b64decode(encrypted_msg["ciphertext"])

            # Key chain handling
            if recv_chain_key is None:
                shared_key = compute_shared_key(ek_private, new_peer_ek_public)
                recv_root_key, recv_chain_key = kdf_root_key(shared_key, b"\x00" * 32)
            elif new_peer_ek_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) != peer_ek_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ):
                shared_key = compute_shared_key(ek_private, new_peer_ek_public)
                recv_root_key, recv_chain_key = kdf_root_key(shared_key, recv_root_key)
                peer_ek_public = new_peer_ek_public
            
            # Update stored peer key
            # Chain key step
            recv_chain_key, message_key = kdf_chain_key(recv_chain_key)

            # Decrypt
            plaintext = decrypt_message(message_key, nonce, ciphertext)

            with patch_stdout():
                print(f"{encrypted_msg['sender']}: {plaintext}")
        except Exception as err:
            with patch_stdout():
                print(f"[ERROR] {err}")
            break




''' 
    Input: python3 <username> <IP address or DNS URL> <port>
'''
if __name__ == "__main__":
    # Process the arguments
    if len(sys.argv) != 4:
        print("Usage: python client.py <username> <IP address or DNS URL> <port>")
        sys.exit(1)

    USERNAME = sys.argv[1]
    print(f"Username has been configured to {USERNAME}")
    HOST = sys.argv[2]
    PORT = int(sys.argv[3])
    print(f"Configured to {HOST}:{PORT}")

    # IPv4 and TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((HOST, PORT))

    '''
        Assuming we are connected, we need to exchange public key
    '''
    # Create the Identity Key
    IK_PRIVATE, IK_PUBLIC = generate_X3DH_keypair()
    # Create Ephemeral Key
    ek_private, ek_public = generate_X3DH_keypair()

    ''' START X3DH '''
    # send over Public Identity Key, Public Ephemeral Key 
        # Identity Key (Long term used for idenifying the person, first connection is just sending and second time connection is verification)
        # Ephemeral Key (For every message sent)
    '''
        sending public key during X3DH
        {
            "type": "X3DH_init",
            "username": "alice",
            "ik_public": "<base64-encoded IK>",
            "ek_public": "<base64-encoded EK>"
        }
    '''
    send_json(client_socket,{"type": "X3DH_init", "username": USERNAME, "ik_public": serialize_key(IK_PUBLIC), "ek_public":serialize_key(ek_public)})
    print(f"sent X3DH init")
    # send the get request for other peer
    '''
        GET request for peer 
        {
          "type": "X3DH_get",
          "requester": "bob"
        }
    '''
    send_json(client_socket, {"type": "X3DH_get","requester": USERNAME})
    print("sent GET request for key")
    # Receive the peer key
    '''
        server should respond with:
        {
            "type": "X3DH_peer",
            "username": "alice",
            "ik_public": "<base64-encoded IK>",
            "ek_public": "<base64-encoded EK>"
        }
    '''
    received_peer_json = recv_json(client_socket)
    print("Received the peer info.... X3DH successful")
    '''
        X3DH complete
    '''

    ''' DH DRA setup '''

    peer_ek_public = deserialize_key(received_peer_json["ek_public"])

    current_peer_ek = peer_ek_public
    print(f"peer_ek_public is set to: {serialize_key(peer_ek_public)}\n")

    
    threading.Thread(target=recv_messages, args=(client_socket,), daemon=True).start()
    # print(f"sending chain is: {send_chain_key}, recv chain is: {recv_chain_key}")
    '''
        DH DRA continous starts
    '''
    while True:
        try:
            # Prompt the user to type in message
            full_msg = session.prompt("You: ")

            current_peer_ek = peer_ek_public

            if send_chain_key == None:
                # Compute the shared secret key DH(sender's private EK, receiver's public EK)
                shared_key = compute_shared_key(ek_private, current_peer_ek)
                # Initial root key. Default to 32 null bytes
                send_root_key, send_chain_key = kdf_root_key(shared_key, b"\x00" * 32)
            else:
                ek_private, ek_public = generate_X3DH_keypair()
                ek_public_b64 = serialize_key(ek_public)
                shared_key = compute_shared_key(ek_private, current_peer_ek)
                send_root_key, send_chain_key = kdf_root_key(shared_key, send_root_key)
            ''''
            sending format for chat json
            {
                "type": "chat",
                "sender": "alice",
                "ek_public": "<base64-encoded ephemeral public key>",
                "nonce": "<base64-encoded nonce>",
                "ciphertext": "<base64-encoded ciphertext>"
            }
            '''
            # Generate message key and new send chain key
            send_chain_key, message_key = kdf_chain_key(send_chain_key)

            # print(f"encrypting using following:\n\n shared_key: {shared_key} \n\n send_chain_key: {send_chain_key}\n\n message_key: {message_key}\n{"-"*32}")

            # TODO encryption here
            nonce, ciphertext = encrypt_message(message_key, full_msg)


            ek_public_b64 = serialize_key(ek_public)

            # send the json for the chat
            send_json(client_socket, {
                "type": "chat", 
                "sender": USERNAME, 
                "ek_public": ek_public_b64, 
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()
            })

        except (KeyboardInterrupt, EOFError):
            print("\n[INFO] Disconnecting.")
            client_socket.close()
            break