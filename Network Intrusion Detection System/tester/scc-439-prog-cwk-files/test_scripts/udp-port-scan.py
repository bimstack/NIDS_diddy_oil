"""
Script Name: udp-port-scan.py
Description: A simple Python script that performs a vertical UDP scan of a specified ports on a target computer.
Author: Paul Smith (Lancaster University)
Date: 2025-01-09
Version: 1.0
"""

from scapy.all import *
from scapy.all import IP, ICMP, UDP
import argparse

def udp_scan(ip_address, start_port, end_port):
    """
    Perform a vertical UDP scan on a specified IP address.

    Args:
        ip_address (str): Target IP address.
        start_port (int): Starting port number.
        end_port (int): Ending port number.
    """
    print(f"Starting UDP scan on {ip_address} from port {start_port} to {end_port}...")

    for port in range(start_port, end_port + 1):
        packet = IP(dst=ip_address)/UDP(dport=port)

        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            print(f"Port {port}: No response (open|filtered)")
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code

            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                print(f"Port {port}: Filtered (ICMP unreachable received)")
            else:
                print(f"Port {port}: ICMP response received (type {icmp_type}, code {icmp_code})")
        else:
            print(f"Port {port}: Unexpected response received")

def main():
    """
    Main function of the program. It collects arguments and calls the udp_scan function.
    """
    # Parse the argument from the command line
    parser = argparse.ArgumentParser(description="A simple script that scans a target IP address using UDP packets on a specified port range")
    parser.add_argument("target_ip", help="The target IP address, e.g. 172.20.0.2")
    parser.add_argument("start_port", help="The lowest port number to scan, e.g. 10")
    parser.add_argument("end_port", help="The highest port number to scan, e.g. 8000")
    args = parser.parse_args()

    start_port = int(args.start_port)
    end_port = int(args.end_port)

    # Validate port range and - if okay - start the scanning
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Ports must be between 1 and 65535, and start_port <= end_port.")
    else:
        udp_scan(args.target_ip, start_port, end_port)

if __name__ == "__main__":
        main()

