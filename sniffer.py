import socket
import struct
import os


def is_valid_ip(ip_address):
    octets = ip_address.split('.')
    if len(octets) != 4:
        return False
    return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)


def get_ip_address(supposedly_address):
    ip_address = supposedly_address
    if not is_valid_ip(supposedly_address) and supposedly_address != '0.0.0.0':
        try:
            ip_address = socket.gethostbyname(supposedly_address)
        except socket.gaierror:
            ip_address = False
        if not ip_address:
            print(f"{ip_address} is not a valid IP address or host name")
            return False
    elif supposedly_address == '0.0.0.0':
        return '0.0.0.0'
    return ip_address


class PacketSniffer:
    def __init__(self, local_ip_address=''):
        ip_address = get_ip_address(local_ip_address)
        if not ip_address:
            self.local_address = False
        else:
            self.local_address = ip_address
        try:
            sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("Completed")
        except socket.error as msg:
            print(f"Socket could not be created. Error Code : " + str(msg))
        else:
            print("In Else-block")





if __name__ == '__main__':
    packet_sniffer = PacketSniffer("255.255.255.255")
    print(packet_sniffer.local_address)
