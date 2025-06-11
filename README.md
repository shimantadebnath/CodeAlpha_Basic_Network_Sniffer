# CodeAlpha_Basic_Network_Sniffer
  Python-based network packet sniffer tools: a command-line script and a PyQt5 GUI app. They capture and analyze Ethernet, IPv4, TCP, UDP, and ICMP packets in real-time, helping users learn basic network traffic inspection and packet parsing techniques.


# Basic Packet Sniffer

A Python-based network packet sniffer tool that captures and analyzes Ethernet, IPv4, TCP, UDP, and ICMP packets.  
Includes two versions:
- **CLI version** (`packet_sniffer.py`) — runs in the terminal and prints packet details.
- **GUI version** (`sniff_packet.py`) — a PyQt5-based graphical interface to display packet data in a table.

---

## Features

- Captures raw network packets using raw sockets (Linux compatible).
- Parses Ethernet, IPv4, TCP, UDP, and ICMP headers.
- Decodes HTTP traffic inside TCP packets (port 80).
- Displays packet metadata such as MAC addresses, IP addresses, ports, flags, and payload data.
- GUI allows start/stop packet capture and displays data in an easy-to-read table.

---

## Requirements

- Python 3.x
- PyQt5 (for GUI version)

---

## Installation

Install PyQt5 for the GUI version:

```bash
pip install pyqt5


Linkedin - https://www.linkedin.com/in/shimantadebnath/

Feel free to contact me for any inquiries or suggestions regarding Basic Packet Sniffer. Thank you for your interest!
