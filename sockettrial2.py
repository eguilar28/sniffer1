# -*- coding: utf-8 -*-


import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# Target subnet (reduced for quicker testing)
SUBNET = '192.168.1.0/30'  # Testing with a smaller subnet
# Magic string for identifying responses
MESSAGE = 'IP address'

class IP:
    def __init__(self, raw_data):
        header = struct.unpack('<BBHHHBBH4s4s', raw_data)
        self.ihl = header[0] & 0xF  # Header Length
        self.src_address = socket.inet_ntoa(header[8])
        self.dst_address = socket.inet_ntoa(header[9])
        self.protocol = header[6]

class ICMP:
    def __init__(self, raw_data):
        header = struct.unpack('<BBHHH', raw_data)
        self.type = header[0]
        self.code = header[1]

# Function to send UDP packets to every IP in the subnet
"""def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))
            print(f"Sent UDP packet to {ip}")  # Confirmation of packet sent
"""
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))
            print(f"Sent UDP packet to {ip}")  # Confirmation of packet sent
            time.sleep(1)  # Wait for 1 second before sending the next packet

class Scanner:
    def __init__(self, host):
        self.host = host
        # Determine socket protocol based on OS
        socket_protocol = socket.IPPROTO_IP if os.name == 'nt' else socket.IPPROTO_ICMP

        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
            self.socket.bind((host, 0))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode on Windows
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        except PermissionError:
            print("Error: Requires administrator privileges to create raw sockets.")
            sys.exit(1)
        except OSError as e:
            print(f"Socket error: {e}")
            sys.exit(1)

    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # Capture a packet
                raw_buffer = self.socket.recvfrom(65535)[0]
                print("Packet captured")  # Confirm packet capture
                ip_header = IP(raw_buffer[:20])

                # Process ICMP packets only
                if ip_header.protocol == socket.IPPROTO_ICMP:
                    print("ICMP packet detected")  # Debugging for ICMP packets
                    offset = ip_header.ihl * 4
                    icmp_header = ICMP(raw_buffer[offset:offset + 8])

                    # Check for ICMP Destination Unreachable (Type 3, Code 3)
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        src_ip = ip_header.src_address
                        if ipaddress.ip_address(src_ip) in ipaddress.IPv4Network(SUBNET):
                            # Verify if the received message matches the sent message
                            if raw_buffer[-len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                if src_ip != self.host and src_ip not in hosts_up:
                                    hosts_up.add(src_ip)
                                    print(f'Host Up: {src_ip}')  # Expected output
                else:
                    print("Non-ICMP packet detected")  # Debugging for non-ICMP packets

        except KeyboardInterrupt:
            # Stop sniffing on interrupt
            self.shutdown(hosts_up)

    def shutdown(self, hosts_up):
        # Handle cleanup on exit
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print('\nUser interrupted.')
        if hosts_up:
            print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
        print('')
        sys.exit()

if __name__ == '__main__':
    # Get host IP automatically or from command line arguments
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = socket.gethostbyname(socket.gethostname())

    scanner = Scanner(host)

    # Start UDP sender thread
    t = threading.Thread(target=udp_sender)
    t.start()

    # Allow more time for UDP packets to be sent
    time.sleep(10)  # Increased delay

    # Start sniffing for responses
    scanner.sniff()
