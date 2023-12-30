
# https://gist.github.com/davidlares/e841c0f9d9b31f3cd8859575d061c467
# https://raw.githubusercontent.com/vinayrp1/TCP-IP-implementation-using-RAW-sockets/master/rawhttpget.py

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# we expect netcat in front sending 150kB of data, nothing fancy

import socket
import struct
import sys
import time

assert (len(sys.argv) > 2)

interface = "enx00155d343104"
mac_src = b"\x00\x15\x5d\x34\x31\x04"
mac_dst = b"\x00\x15\x5d\x34\x31\x15"
ip_src = "192.168.254.1"
ip_dst = "10.224.123.2"
tcp_src = int(sys.argv[1])
tcp_dst = 8000
start_seq = int(sys.argv[2])

socket_send = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
socket_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

socket_send.bind((interface, socket.SOCK_RAW))
socket_recv.bind((ip_src, socket.SOCK_RAW))


def get_checksum(data):
    sum = 0
    for index in range(0,len(data),2):
        word = ((data[index]) << 8) + ((data[index+1]))
        sum = sum + word
        sum = (sum >> 16) + (sum & 0xffff);
    sum = ~sum & 0xffff
    return sum

IHL = 5
IP_VERSION = 4
TYPE_OF_SERVICE = 0
DONT_FRAGMENT = 0
IP_HDR_LEN = 20
IHL_VERSION = IHL + (IP_VERSION << 4)
TTL = 42
MSS = 1460
WSCALE = 7

def build_first_syn():
    packet = struct.pack("!6s6s2s", mac_dst, mac_src, b'\x08\x00')
    payload_len = 32
    cksum = 0
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, 20+payload_len, TTL, DONT_FRAGMENT, 64, socket.IPPROTO_TCP, cksum, socket.inet_aton(ip_src),socket.inet_aton(ip_dst))
    cksum = get_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, 20+payload_len, TTL, DONT_FRAGMENT, 64, socket.IPPROTO_TCP, cksum, socket.inet_aton(ip_src),socket.inet_aton(ip_dst))
    packet = packet + ip_header
    offset = 8 << 4
    tcp_flags = 0x2  # SYN
    cksum = 0
    # MSS option, SACK, nop, wscale=7, nop, nop. Timestamps missing not sure that matters
    tcp_header = struct.pack('!HHLLBBHHHBBHBBBBBBBB', tcp_src, tcp_dst, start_seq, 1, offset, tcp_flags, 256, cksum, 0, 2, 4, MSS, 4, 2, 1, 3, 3, WSCALE, 1, 1)
    pseudo_hdr = struct.pack('!4s4sBBH', socket.inet_aton(ip_src), socket.inet_aton(ip_dst), 0, socket.IPPROTO_TCP, payload_len)
    cksum = get_checksum(pseudo_hdr + tcp_header)
    tcp_header = struct.pack('!HHLLBBHHHBBHBBBBBBBB', tcp_src, tcp_dst, start_seq, 1, offset, tcp_flags, 256, cksum, 0, 2, 4, MSS, 4, 2, 1, 3, 3, WSCALE, 1, 1)
    return packet + tcp_header

def receive_ack():
    # should be a SYN-ACK the first time
    recv_packet = socket_recv.recv(65565)
    ipHeader = recv_packet[0:20]
    ipHdr=struct.unpack('!BBHHHBBH4s4s', ipHeader)
    tcpHeader = recv_packet[20:40]
    tcpHdr=struct.unpack('!HHLLBBHHH',tcpHeader)
    if tcpHdr[0] != tcp_dst or tcpHdr[1] != tcp_src or tcpHdr[2] == 0 or (tcpHdr[5] & 0x5 > 0):
        print("ignored", ipHdr, tcpHdr)
        return (0, 0)
    payloadLen =  (ipHdr[2] - 20 - ((tcpHdr[4] &0xF0)>> 2))
    print("received", payloadLen, ipHdr, tcpHdr)

    return (tcpHdr[2], payloadLen)

def build_ack(ack, win):
    packet = struct.pack("!6s6s2s", mac_dst, mac_src, b'\x08\x00')
    cksum = 0
    payload_len = 20
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, 20+payload_len, TTL, DONT_FRAGMENT, 64, socket.IPPROTO_TCP, cksum, socket.inet_aton(ip_src),socket.inet_aton(ip_dst))
    cksum = get_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, 20+payload_len, TTL, DONT_FRAGMENT, 64, socket.IPPROTO_TCP, cksum, socket.inet_aton(ip_src),socket.inet_aton(ip_dst))
    packet = packet + ip_header
    offset = 5 << 4
    tcp_flags = 0x10  # ACK
    cksum = 0
    tcp_header = struct.pack('!HHLLBBHHH', tcp_src, tcp_dst, start_seq+1, ack, offset, tcp_flags, win, cksum, 0)
    pseudo_hdr = struct.pack('!4s4sBBH', socket.inet_aton(ip_src), socket.inet_aton(ip_dst), 0, socket.IPPROTO_TCP, 20)
    cksum = get_checksum(pseudo_hdr + tcp_header)
    tcp_header = struct.pack('!HHLLBBHHH', tcp_src, tcp_dst, start_seq+1, ack, offset, tcp_flags, win, cksum, 0)
    return packet + tcp_header

# send the SYN
socket_send.send(build_first_syn() + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ack, llen = receive_ack()
assert (llen == 0)

# complete the handshake:
socket_send.send(build_ack(ack+1, 256) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

win = 10000
counter = 0
totallen = 0
while True:
    ack, llen = receive_ack()
    if ack == 0:
        continue
    totallen += llen
    counter += 1
    if totallen < 20000:
        # ack every single packet at the beginning of the connection
        socket_send.send(build_ack(ack + llen, win) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    elif totallen == 1024 * 150:
        # ack the very last packet
        socket_send.send(build_ack(ack + llen, win) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        print ("done!!")
    else:
        print ("skipping", totallen, llen)
        

