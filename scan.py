from scapy.all import IP, TCP, sr1, sr

def port_scan(target_ip, port_range):
    for port in range(1, port_range + 1):
        pkt = IP(dst=target_ip) / TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # Flags 0x12 means SYN-ACK received, port is open
            print(f"Port {port} is open on {target_ip}")
            sr(IP(dst=target_ip) / TCP(dport=port, flags='R'), timeout=1, verbose=0)  # Send RST to close connection
        elif response and response.getlayer(TCP).flags == 0x14:
            # Flags 0x14 means RST-ACK received, port is closed
            print(f"Port {port} is closed on {target_ip}")

# Example usage: Scan ports 1-30 on '192.168.1.1'
port_scan('198.24.51.24', 50)