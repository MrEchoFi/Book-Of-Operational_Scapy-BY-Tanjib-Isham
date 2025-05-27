from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

send(IP(dst="198.23.51.26")/TCP(dport=80,flags="S")/Raw(load="GET / HTTP/1.1\r\n\r\n"),loop=1)
