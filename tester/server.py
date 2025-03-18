import socket   # For network Communication
import struct   # Binray Data Packing
from Crypto.Cipher import AES   # Encryption Method
from Crypto.Util.Padding import unpad   # Data Padding for encryption
import json

# Server configuration section
HOST = '0.0.0.0'    # Open for connection from all IP addresses
PORT = 8080     # Defines network port for communication
KEY = b'16BytesSecretKey'  # Must match client key

# Receive exact number of bytes
def recv_exact(sock, length):
    data = b''                                          # Empty byte string
    while len(data) < length:                           # This loop continues receiving data until the total length of the received data is equal to the requested length
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed")  # If no data is received ConnectionError is raised with the message "Connection closed."
        data += packet                                  # Adds the received packet to the data variable
    return data

# Process incoming alerts
def handle_alert(conn):
    try:
        # Receive IV (16 bytes)
        iv = recv_exact(conn, 16)
        
        # Receive ciphertext length (4 bytes)
        ct_length = struct.unpack('!I', recv_exact(conn, 4))[0]
        
        # Receive ciphertext
        ciphertext = recv_exact(conn, ct_length)
        
        # Decrypt data
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)          # This creates a new AES cipher object
        padded_plaintext = cipher.decrypt(ciphertext)       # This line decrypts ciphertext using AES cipher object in CBC mode
        plaintext = unpad(padded_plaintext, AES.block_size) # This removes the padding added during encryption
        
        # This is how security alert look like...
        alert = json.loads(plaintext.decode())
        print("\n=== SECURITY ALERT ===")
        print(f"Type: {alert['type']}")
        print(f"Time: {alert['timestamp']}")
        print(f"Details: {alert['message']}")
        print(f"Origin: {alert['source']}")
        print("======================\n")
        
    except Exception as e:                          # Error handling
        print(f"Error processing alert: {str(e)}")
    finally:
        conn.close()

# Main server loop
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    # Creates a new socket while ensuring that socket is properly closed when the block is done executing
        s.bind((HOST, PORT))                                        # Binds the socket to a specific address and port
        s.listen()                                                  # Prepares the socket to listen for incoming connections
        print(f"Server is online : {HOST}:{PORT}")                  # Prints a message indicating that the server is now listening
        while True:                                                 # Continuously waits for incoming connections
            conn, addr = s.accept()                                 # Accepts an incoming connection
            print(f"Connection from {addr[0]}:{addr[1]}")           # Prints the IP address and port number of the connected client
            handle_alert(conn)                                      # Process the connection

if __name__ == "__main__":
    start_server()