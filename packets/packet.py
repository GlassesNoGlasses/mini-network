from enum import Enum

# constants
PACKET_SIZE = 1024
HEADER_SIZE = 8
MAX_DATA_SIZE = PACKET_SIZE - HEADER_SIZE

class PACKET_TYPE(Enum):
    ICMP = 0
    TCP = 1
    UDP = 2
    ARP = 3
    DNS = 4
    HTTP = 5
    HTTPS = 6


class Packet():
    def __init__(self, data: str | bytes, type = PACKET_TYPE):
        self.data = data
        self.type = type

    def __str__(self):
        return f"Packet({self.data})"
    

class PacketHeader():
    def __init__(self, src: str, dest: str, type: PACKET_TYPE):
        self.src = src
        self.dest = dest
        self.type = type

    def __str__(self):
        return f"PacketHeader({self.src}, {self.dest}, {self.type})"


class PacketBuilder():
    def __init__(self, src: str, dest: str, type: PACKET_TYPE):
        self.header = PacketHeader(src, dest, type)
        self.data = None

    def add_data(self, data: str | bytes):
        self.data = data

    def build(self):
        return Packet(self.data, self.header.type)
