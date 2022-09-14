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


class EthernetFrame:
    @staticmethod
    def get_mac_address(raw_addr):
        str_bytes = map("{:02x}".format, raw_addr)
        return ':'.join(str_bytes).upper()

    def eth_header(self):
        dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.raw_data[:14])
        return self.get_mac_address(dst_mac), self.get_mac_address(src_mac), socket.ntohs(proto)

    def get_ethernet_data(self):
        return self.data[14:]

    def __str__(self):
        return f"\nEthernet Frame:\n\t\tDestination: {self.dst_mac}\tSource: {self.src_mac}\tProtocol: {self.proto}"

    def __init__(self, raw_data):
        self.data = raw_data
        self.dst_mac, self.src_mac, self.proto = self.eth_header()


class IPPacket:
    @staticmethod
    def get_ip_address(address):
        return '.'.join(map(str, address))

    def __init__(self, raw_data):
        ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
        self.version = ip_header[0] >> 4
        self.hLen = ip_header[0] & 0xF
        self.tos = ip_header[1]
        self.total_len = ip_header[2]
        self.unique_id = ip_header[3]
        self.offset_flags = ip_header[4]
        self.ttl = ip_header[5]
        self.proto = socket.ntohs(ip_header[6])  # TODO: нужно проверить идею с порядком в сети
        self.checksum = ip_header[7]
        self.src_address = get_ip_address(ip_header[8])
        self.dst_address = get_ip_address(ip_header[9])

    def __str__(self):
        return f"\n\tIP Packet:\n\t\t\tSource: {self.src_address}\tDestination: {self.dst_address}\t Proto: {self.proto}"


class PacketSniffer:
    def __init__(self, local_ip_address=''):
        ip_address = get_ip_address(local_ip_address)
        if not ip_address:
            self.local_address = False
        else:
            self.local_address = ip_address
        self.sniff_socket = False
        try:
            self.sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("Completed")
        except socket.error as msg:
            print(f"Socket could not be created. Error Code : " + str(msg))
        else:
            print("In Else-block")

    def start_server(self):
        print("Starting Sniffer ...")
        while True:
            raw_data = self.sniff_socket.recvfrom(65535)[0]
            ethernet_frame = EthernetFrame(raw_data)
            print(ethernet_frame)
            if ethernet_frame.proto == 8:
                ip_packet = IPPacket(ethernet_frame.get_ethernet_data())
                print(ip_packet)


if __name__ == '__main__':
    packet_sniffer = PacketSniffer("255.255.255.255")
    print(packet_sniffer.local_address)
