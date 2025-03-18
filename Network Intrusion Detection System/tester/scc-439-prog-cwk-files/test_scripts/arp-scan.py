"""
Script Name: arp-scan.py
Description: A simple program that performs an ARP scan using scapy. Require superuser privileges to execute.
Author: Paul Smith (Lancaster University)
Date: 2025-01-09
Version: 1.0
"""

from scapy.all import ARP, Ether, srp
import argparse

def scan_network(ip_range):
    """
    Scans the specified IP range for active devices and retrieves their MAC addresses.
    :param ip_range: IP range to scan (e.g. "172.20.0.0/24")
    """
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    # Create an Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP request and Ethernet frame
    arp_request_broadcast = broadcast / arp_request

    print(f"Scanning network: {ip_range}...\n")

    # Send the packets and capture the responses
    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

    # Parse the responses
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Display results
    if devices:
        print("Devices found on the network:")
        print("IP Address\t\tMAC Address")
        print("-------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found on the network.")

def main():
    """
    Main function of the program that takes an argument (an IP address range) and
    calls the scan_network function to start scanning the specified range
    """
    # Parse the argument from the command line
    parser = argparse.ArgumentParser(description="A simple ARP scanning application that requires one argument, an IP address range")
    parser.add_argument("ip_range", help="An IP address range, e.g. 172.20.0.0/24")
    args = parser.parse_args()
    scan_network(args.ip_range)

if __name__ == "__main__":
    main()


