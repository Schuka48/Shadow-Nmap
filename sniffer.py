import socket
import struct
import os
from datetime import datetime


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
        dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.data[:14])
        return self.get_mac_address(dst_mac), self.get_mac_address(src_mac), socket.ntohs(proto)

    def get_data(self):
        return self.data[14:]

    def __str__(self):
        return f"{print('-' * 175)}\n{datetime.now()}\nEthernet Frame:\n\t\tDestination: {self.dst_mac}\t" \
               f"Source: {self.src_mac}\tProtocol: {self.proto}"

    def __init__(self, raw_data):
        self.data = raw_data
        self.dst_mac, self.src_mac, self.proto = self.eth_header()


class IPPacket:
    @staticmethod
    def get_address(address):
        return '.'.join(map(str, address))

    def __init__(self, raw_data):
        ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
        self.version = ip_header[0] >> 4
        self.hLen = ip_header[0] & 0xF
        self.header_len = self.hLen * 4
        self.tos = ip_header[1]
        self.total_len = ip_header[2]
        self.unique_id = ip_header[3]
        self.offset_flags = ip_header[4]
        self.ttl = ip_header[5]
        self.proto = ip_header[6]  # TODO: нужно проверить идею с порядком в сети
        self.checksum = ip_header[7]
        self.src_address = self.get_address(ip_header[8])
        self.dst_address = self.get_address(ip_header[9])
        self.data = raw_data[self.header_len:]

    def __str__(self):
        return f"\tIP Packet:\n\t\t\tSource: {self.src_address}\tDestination: {self.dst_address}\t Proto: {self.proto}"

    def get_data(self):
        return self.data


class ICMP:
    def __init__(self, raw_data):
        icmp_header = struct.unpack("!ssHL8x", raw_data[:16])
        self.type = icmp_header[0]
        self.code = icmp_header[1]
        self.checksum = icmp_header[2]
        self.data = raw_data[16:]

    def __str__(self):
        return f"\t\t\t\tICMP\t\tChecksum: {hex(self.checksum)}\tData: {self.data}\tLen: {len(self.data)}"


class TCP:
    def __init__(self, raw_data):
        tcp_header = struct.unpack("!HHLLH", raw_data[:14])
        self.src_port = tcp_header[0]
        self.dst_port = tcp_header[1]
        self.sequence = tcp_header[2]
        self.acknowledgment = tcp_header[3]
        self.offset_reserved_flags = tcp_header[4]
        self.offset = (self.offset_reserved_flags >> 12) * 4
        self.reserved = (self.offset_reserved_flags >> 8) & 15
        self.flag_urg = (self.offset_reserved_flags & 32) >> 5
        self.flag_ack = (self.offset_reserved_flags & 16) >> 4
        self.flag_psh = (self.offset_reserved_flags & 8) >> 3
        self.flag_rst = (self.offset_reserved_flags & 4) >> 2
        self.flag_syn = (self.offset_reserved_flags & 2) >> 1
        self.flag_fin = self.offset_reserved_flags & 1
        self.data = raw_data[self.offset:]

    def get_data(self):
        return self.data

    def __str__(self):
        return f"\t\tTCP\t Src_Port: {self.src_port}\tDst_Port: {self.dst_port}\n" \
               f"\t\t\t Sequence: {self.sequence}\tAcknowledgment: {self.acknowledgment}\n" \
               f"\t\t\t Flags URG:{self.flag_urg} ACK:{self.flag_ack} PSH:{self.flag_psh} " \
               f"RST:{self.flag_rst} SYN:{self.flag_syn} FIN:{self.flag_fin}"


class UDP:
    def __init__(self, raw_data):
        udp_header = struct.unpack("!HHHH", raw_data[:8])
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.length = udp_header[2]  #  Переменная обозначает длину всего UDP-пакета, учитывая заголовок
        self.chk_sum = udp_header[3]
        self.data = raw_data[8:]

    def get_data(self):
        return self.data

    def __str__(self):
        return f"\t\tUDP\t Src_Port: {self.src_port}\tDst_Port: {self.dst_port}\tLength: {self.length}"


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
        self.finished = False

    def sniffer_handler(self):
        raw_data = self.sniff_socket.recvfrom(65535)[0]
        ethernet_frame = EthernetFrame(raw_data)
        # print(ethernet_frame)
        if ethernet_frame.proto == 8:
            ip_packet = IPPacket(ethernet_frame.get_data())
            # print(ip_packet)
            if ip_packet.proto == 1:
                icmp_packet = ICMP(ip_packet.get_data())
                # print(icmp_packet)
            elif ip_packet.proto == 6:
                if ip_packet.dst_address == "10.33.102.104":
                    tcp_packet = TCP(ip_packet.get_data())
                if ip_packet.dst_address == "10.33.102.104" and tcp_packet.flag_syn == 1:
                    print(ethernet_frame)
                    print(ip_packet)
                    print(tcp_packet)
            elif ip_packet.proto == 17:
                udp_packet = UDP(ip_packet.get_data())
                print(udp_packet)

    def start_sniffer(self):
        print("Starting Sniffer ...")
        try:
            while not self.finished:
                self.sniffer_handler()
        except KeyboardInterrupt:
            print("\nStop Sniffer ...")
            print("Good By!")

    def stop_sniffer(self):
        print("\nStopping Sniffer ...")
        self.finished = True


if __name__ == '__main__':
    packet_sniffer = PacketSniffer()
    packet_sniffer.start_sniffer()

