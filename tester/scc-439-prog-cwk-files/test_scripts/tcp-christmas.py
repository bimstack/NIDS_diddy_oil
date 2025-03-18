"""
Script Name: tcp-christmas.py
Description: A simple Python script that send TCP Christmas packets to a specified IP address and port number.
Author: Paul Smith (Lancaster University)
Date: 2025-01-09
Version: 1.0
"""

from scapy.all import IP, TCP, send
import argparse

def send_christmas_tree_packets(target_ip, target_port, count):
    """
    Sends a specified number of TCP Christmas tree packets to a target IP and port.

    :param target_ip: The IP address of the target.
    :param target_port: The port of the target.
    :param count: The number of packets to send.
    """
    # Construct the TCP packet with FIN, PSH, and URG flags set
    tcp_flags = 'FPU'
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags=tcp_flags)

    print(f"Sending {count} TCP Christmas tree packets to {target_ip}:{target_port}...\n")

    # Send the packets
    for i in range(count):
        send(packet, verbose=False)
        print(f"Packet {i + 1} sent.")

    print("\nAll packets sent.")

def main():
    """
    Main function of the program. It collects arguments and calls the send_christmas_tree_packets function
    """
    # Parse the argument from the command line
    parser = argparse.ArgumentParser(description="A simple script that send TCP Christmas packets to a specified IP address and port number.")
    parser.add_argument("target_ip", help="The target IP address, e.g. 172.20.0.2")
    parser.add_argument("target_port", help="The port number to send the packets to, e.g. 80")
    parser.add_argument("packet_count", help="The number of packets to send, e.g. 1000")
    args = parser.parse_args()

    target_port = int(args.target_port)
    packet_count = int(args.packet_count)

    # Check the port number is rationale and - if so - call the send_udp_packets function
    if target_port < 1 or target_port > 65535:
        print("Invalid port number. Ports must be between 1 and 65535.")
    else:
        send_christmas_tree_packets(args.target_ip, target_port, packet_count)

if __name__ == "__main__":
        main()
