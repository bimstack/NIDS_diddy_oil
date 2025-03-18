import scapy.all as scapy                       # For Packet sniffing
import time                                     # Timestamp
import socket                                   # For network Communication
import struct                                   # Binray Data Packing
from scapy.layers.inet import IP, TCP, UDP      # Layers of Network Protocol
from scapy.layers.l2 import ARP                 # ARP protocol
from collections import defaultdict             # Data Tracking
from Crypto.Cipher import AES                   # Encryption Method
from Crypto.Util.Padding import pad             # Data Padding for encryption
from Crypto.Random import get_random_bytes      # To secure random values
import json

# Configuration Section
SERVER_IP = '172.20.0.3'    # Destination of server IP
SERVER_PORT = 8080          # Defines network port for communication
KEY = b'16BytesSecretKey'   # 16-byte AES key for secure communication

# Detection thresholds
ARP_SCAN_THRESHOLD = 15         # Alert if ARP scan is detected by getting 15 or more ARP requests
CHRISTMAS_TREE_THRESHOLD = 5    # Alert if TCP-Christmas scan is detected by getting 5 or more Christmas packets
PORT_SCAN_THRESHOLD = 5         # Alert if 5 or more unique ports are accessed
UDP_FLOOD_THRESHOLD = 50        # Alert if 50 or more UDP packets are sent

# Global state variables
arp_log = defaultdict(list)                 # Tracks ARP requests
christmas_log = defaultdict(list)           # Logs christmas tree scan packets
port_scan_log = defaultdict(list)           # Logs attempted connections to different ports to detect port scanning
udp_log = defaultdict(list)                 # Stores information about UDP packets received
alert_cool = {}                        # Prevents sending excessive alerts for repeated attacks from the same IP

# Main packet analysis function
def process_pack(packet):             # Define function
    if packet.haslayer(IP):             # Checks if the packet has an IP layer
        src_ip = packet[IP].src         # Extracts the source IP address of the packet
        
        # ARP Scan detection
    if packet.haslayer(ARP) and packet[ARP].op == 1:                # Checks if the packet is an ARP request
        src_mac = packet[ARP].hwsrc
        up_log(arp_log, src_mac)
        if threshold_checker(arp_log, src_mac, ARP_SCAN_THRESHOLD):   # Logs the attack attempt in arp_log using the source MAC address
            alert_send("ARP Scan", src_mac, arp_log)                # If the number of requests from a MAC address exceeds it sends an alert
        
        # TCP-Christmas Scan detection
    if packet.haslayer(TCP) and all(f in packet[TCP].flags for f in ['F', 'P', 'U']):   # Checks if the TCP packet has the flags
        up_log(christmas_log, src_ip)
        if threshold_checker(christmas_log, src_ip, CHRISTMAS_TREE_THRESHOLD):            # Logs the attack attempt in christmas_log
                alert_send("CHRISTMAS Scan", src_ip, christmas_log)                         # If the threshold is exceeded it sends an alert
        
        # Port Scan detection
    if packet.haslayer(TCP):
        trk_port_act(src_ip, packet[TCP].dport)  # Extracts the destination port and logs it
    elif packet.haslayer(UDP):
        trk_port_act(src_ip, packet[UDP].dport)  # Extracts the destination port and logs it
        
        # UDP Flood detection
    if packet.haslayer(UDP):
        up_log(udp_log, src_ip)
        if threshold_checker(udp_log, src_ip, UDP_FLOOD_THRESHOLD):   # Checks if the source IP has exceeded a threshold
            alert_send("UDP Flood", src_ip, udp_log)                # If the threshold is exceeded it sends an alert

# Tracking port scanning patterns
def trk_port_act(src_ip, port):                                                              # Source IP of packet and destination trying to be acccessed
    current_time = time.time()                                                                      # Used to determine when the port access attempt occurred
    port_scan_log[src_ip].append((port, current_time))                                              # Logs the port access attempt by adding a tuple (port, timestamp)
    port_scan_log[src_ip] = [(p, t) for p, t in port_scan_log[src_ip] if current_time - t < 10]     # Removes old entries keeping only the ones from the last 10 seconds
    unique_ports = len({p for p, t in port_scan_log[src_ip]})                                       # Extracts unique ports from the logged attempts of the source IP
    if unique_ports >= PORT_SCAN_THRESHOLD:                                                         # If the number of unique ports scanned exceeds it triggers an alert
        alert_send("Port Scan", src_ip, port_scan_log)

# Maintain time-windowed logs
def up_log(log_dict, key):
    current_time = time.time()                                              # Gets the current timestamp
    log_dict[key] = [t for t in log_dict[key] if current_time - t < 10]     # Entries older than 10 seconds are discarded
    log_dict[key].append(current_time)                                      # Adds the current timestamp to the log for the given key

# Check if activity exceeds threshold
def threshold_checker(log_dict, key, threshold):  # Counts the number of events recorded
    return len(log_dict[key]) >= threshold

# Central alert handling with cooldown
def alert_send(alert_type, source, log_dict):
    cooldown = 5                                # 5-second cooldown between same alerts
    current_time = time.time()                  # This stores the current time in variable (current_time)
    
    # Check cooldown status
    last_alert = alert_cool.get((source, alert_type), 0)   # Retrieves the time when the alert was last sent for a specific combination
    if current_time - last_alert < cooldown:                    # Difference between the current time and the time of the last alert
        return
    
    # Update cooldown tracker
    alert_cool[(source, alert_type)] = current_time
    
    # This is how alert message will look like...
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    message = f"{alert_type} detected from {source}"
    
    print(f"!!!ALERT!!! : {message} at {timestamp}")
    msg_display({
        "type": alert_type,
        "message": message,
        "timestamp": timestamp,
        "source": "Client"
    })
    
    # Reset tracking for this alert
    log_dict[source].clear()

# Encrypt and transmit alert using AES-CBC
def msg_display(data):
    try:
        plaintext = json.dumps(data).encode()           # Converts the data object into a JSON-formatted string
        padded_data = pad(plaintext, AES.block_size)    # Plaintext is a multiple of the AES block size
        iv = get_random_bytes(16)                       # This generates a random initialization vector (iv) of 16 bytes
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)      # This creates a new AES cipher object
        ciphertext = cipher.encrypt(padded_data)        # This method encrypts the padded plaintext using the AES cipher created in the previous line
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:            # This line opens a new socket connection using IPv4 and the TCP protocol
            s.connect((SERVER_IP, SERVER_PORT))                                 # This connects the socket to server using IP address and port
            s.sendall(iv + struct.pack('!I', len(ciphertext)) + ciphertext)     # (iv) is sent first so the receiver can use it for decryption
    except Exception as e:                                                      # Error handling
        print(f"Alert transmission failed: {str(e)}")

# Start packet capture
def start_sniffing():
    scapy.sniff(prn=process_pack, store=False, filter="ip or arp")    # Captures IP and ARP packets and processes them without storing them

if __name__ == "__main__":
    start_sniffing()