# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from threading import Thread, Event
import socket
import struct
import textwrap

class Ui_Basic_Packet_Sniffer(object):
    def setupUi(self, Basic_Packet_Sniffer):
        Basic_Packet_Sniffer.setObjectName("Basic_Packet_Sniffer")
        Basic_Packet_Sniffer.resize(748, 443)
        self.verticalLayoutWidget = QtWidgets.QWidget(Basic_Packet_Sniffer)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(570, 20, 160, 80))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.ButtonStart = QtWidgets.QPushButton("Start")
        self.ButtonStop = QtWidgets.QPushButton("Stop")
        self.verticalLayout.addWidget(self.ButtonStart)
        self.verticalLayout.addWidget(self.ButtonStop)

        self.tableWidget = QtWidgets.QTableWidget(Basic_Packet_Sniffer)
        self.tableWidget.setGeometry(QtCore.QRect(10, 110, 721, 321))
        self.tableWidget.setColumnCount(20)

        headers = [
            "Dest MAC", "Src MAC", "Protocol", "IPv4 Version", "IPv4 Header Length",
            "IPv4 TTL", "IPv4 Protocol", "Dest IP", "Src IP", "Dest Port",
            "Src Port", "Sequence", "Acknowledgment", "Flags[URG]", "Flags[ACK]",
            "Flags[PSH]", "Flags[RST]", "Flags[SYN]", "Flags[FIN]", "DATA"
        ]

        self.tableWidget.setHorizontalHeaderLabels(headers)
        self.numRow = 0
        QtCore.QMetaObject.connectSlotsByName(Basic_Packet_Sniffer)

    def add_table_item(self, Basic_Packet_Sniffer, data):
        self.tableWidget.setRowCount(self.numRow + 1)
        for i in range(20):
            item = QtWidgets.QTableWidgetItem(str(data[i]))
            self.tableWidget.setItem(self.numRow, i, item)
        self.numRow += 1

def get_mac_addr(mac_raw):
    return ':'.join(map('{:02x}'.format, mac_raw)).upper()

def get_ip(addr):
    return '.'.join(map(str, addr))

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    return get_mac_addr(dest), get_mac_addr(src), socket.htons(prototype), raw_data[14:]

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    return version_header_length, version, header_length, ttl, proto, get_ip(src), get_ip(target), raw_data[header_length:]

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = [(offset_reserved_flags >> i) & 1 for i in reversed(range(6))]  # URG to FIN
    return src_port, dest_port, sequence, acknowledgment, *flags, raw_data[offset:]

def udp_head(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]

def icmp_head(raw_data):
    packet_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return packet_type, code, checksum, raw_data[4:]

def main(ui, Basic_Packet_Sniffer, event):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while not event.is_set():
        raw_data, _ = s.recvfrom(65535)
        data = ["-"] * 20
        dest_mac, src_mac, proto, eth_data = ethernet_head(raw_data)
        data[0], data[1], data[2] = dest_mac, src_mac, proto

        if proto == 8:
            _, version, header_length, ttl, ip_proto, src_ip, dest_ip, ip_data = ipv4_head(eth_data)
            data[3:9] = [version, header_length, ttl, ip_proto, dest_ip, src_ip]

            if ip_proto == 6:  # TCP
                tcp = tcp_head(ip_data)
                data[9:19] = tcp[:-1]
                data[19] = tcp[-1]
            elif ip_proto == 1:  # ICMP
                icmp = icmp_head(ip_data)
                data[19] = f"ICMP: type={icmp[0]}, code={icmp[1]}, checksum={icmp[2]}, data={icmp[3]}"
            elif ip_proto == 17:  # UDP
                udp = udp_head(ip_data)
                data[9:11] = udp[:2]
                data[19] = udp[3]
        else:
            data[19] = eth_data

        ui.add_table_item(Basic_Packet_Sniffer, data)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Basic_Packet_Sniffer = QtWidgets.QDialog()
    ui = Ui_Basic_Packet_Sniffer()
    ui.setupUi(Basic_Packet_Sniffer)

    stop_event = Event()
    sniff_thread = Thread(target=main, args=(ui, Basic_Packet_Sniffer, stop_event))

    ui.ButtonStart.clicked.connect(sniff_thread.start)
    ui.ButtonStop.clicked.connect(stop_event.set)

    Basic_Packet_Sniffer.show()
    sys.exit(app.exec_())
