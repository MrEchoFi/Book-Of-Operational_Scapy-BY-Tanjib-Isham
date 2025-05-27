#!/usr/bin/env python3
"""
Network Traffic Monitor & Active Nmap Scanner for Red/Blue Team Operations

This tool provides two main functionalities:
  1. Passive network traffic capture using Scapy.
  2. Active network scanning using Nmap (via python-nmap module).

Optional logging is available, so you can save captured output to a file for later analysis.

Dependencies:
  - scapy (installed via apt or pip)
  - colorama (installed via pip)
  - python-nmap (to enable nmap scanning; install via `pip3 install python-nmap`)
  - libpcap-dev (if using apt on Ubuntu)

Usage examples:
  • List available interfaces:
      python nettrafficmonitor.py --list

  • Passive traffic monitoring on a specified interface (e.g. "eth0") filtering port 80:
      sudo python3 nettrafficmonitor.py -i eth0 -p 80

  • Run an active Nmap scan on target 192.168.1.0/24, then monitor traffic:
      sudo python3 nettrafficmonitor.py -i eth0 -p 80 -S 192.168.1.0/24

  • Save packet capture output to a log file:
      sudo python3 nettrafficmonitor.py -i eth0 -S 192.168.1.0/24 -o capture.log
"""

import argparse
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from colorama import Fore, Style
import platform
import sys

# Try importing python-nmap; if not installed, notify the user.
try:
    import nmap
except ImportError:
    print(f"{Fore.RED}python-nmap module not found. To use Nmap scanning, install it via 'pip3 install python-nmap'.{Style.RESET_ALL}")
    nmap = None


class TrafficMonitor:
    def __init__(self, interface, port, log_file=None):
        self.interface = interface
        self.port = port
        self.log_file = log_file
        if self.log_file:
            try:
                self.log_handle = open(self.log_file, 'a')
            except Exception as e:
                print(f"{Fore.RED}Error opening log file: {e}{Style.RESET_ALL}")
                self.log_handle = None
        else:
            self.log_handle = None

    def log(self, message):
        # Write message to the log file if logging is enabled.
        if self.log_handle:
            self.log_handle.write(message + "\n")

    def packet_handler(self, packet):
        # Only process packets that have an IP layer.
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Process TCP packets.
            if packet.haslayer(TCP):
                # Filter by port if specified.
                if self.port is None or packet[TCP].sport == self.port or packet[TCP].dport == self.port:
                    output = (f"{Fore.CYAN}TCP Packet - Source IP: {src_ip}, Source Port: {packet[TCP].sport}, "
                              f"Destination IP: {dst_ip}, Destination Port: {packet[TCP].dport}{Style.RESET_ALL}")
                    print(output)
                    self.log(output)
            # Process UDP packets.
            elif packet.haslayer(UDP):
                if self.port is None or packet[UDP].sport == self.port or packet[UDP].dport == self.port:
                    output = (f"{Fore.BLUE}UDP Packet - Source IP: {src_ip}, Source Port: {packet[UDP].sport}, "
                              f"Destination IP: {dst_ip}, Destination Port: {packet[UDP].dport}{Style.RESET_ALL}")
                    print(output)
                    self.log(output)

    def start_monitoring(self, timeout=None):
        print(f"{Fore.GREEN}Network Traffic Monitor by EbweR - Version 1.0{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Starting packet capture on interface: {self.interface}, monitoring port: "
              f"{self.port if self.port else 'All ports'}...{Style.RESET_ALL}")
        # 'store=0' avoids retaining packets in memory.
        sniff(iface=self.interface, prn=self.packet_handler, store=0, timeout=timeout)

    def close(self):
        if self.log_handle:
            self.log_handle.close()


def run_nmap_scan(target, port_range="1-1024"):
    """
    Run an nmap scan on the specified target for the given port range.
    """
    if nmap is None:
        print(f"{Fore.RED}Nmap scanning is not available (python-nmap is not installed).{Style.RESET_ALL}")
        return
    print(f"{Fore.MAGENTA}Starting nmap scan on target: {target} (ports {port_range})...{Style.RESET_ALL}")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, port_range)
    except Exception as e:
        print(f"{Fore.RED}Error during nmap scan: {e}{Style.RESET_ALL}")
        return
    print(f"{Fore.MAGENTA}Nmap scan complete. Results for {target}:{Style.RESET_ALL}")
    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = sorted(scanner[host][proto].keys())
            for port in ports:
                state = scanner[host][proto][port]['state']
                print(f"  Port: {port}\tState: {state}")
    print(f"{Fore.MAGENTA}Nmap scan completed for target: {target}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitoring Tool with integrated Nmap Active Scan feature")
    parser.add_argument("-i", "--interface", type=str,
                        help="Network interface to listen on")
    parser.add_argument("-p", "--port", type=int,
                        help="Port number to filter traffic (optional)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("-S", "--nmap", type=str,
                        help="Target IP or network range for Nmap scan (optional)")
    parser.add_argument("-o", "--output", type=str,
                        help="Log file to output captured data (optional)")
    args = parser.parse_args()

    # List available interfaces if requested.
    if args.list:
        interfaces = get_if_list()
        print("Available interfaces:")
        for iface in interfaces:
            print(f" - {iface}")
        sys.exit(0)

    if args.interface is None:
        print("No interface specified. Use -i <interface> or run with -l to list available interfaces.")
        sys.exit(1)

    print("Running on platform:", platform.system())

    # If an Nmap target is provided, perform an active scan.
    if args.nmap:
        run_nmap_scan(args.nmap)

    # Initialize and start the traffic monitor.
    monitor = TrafficMonitor(interface=args.interface, port=args.port, log_file=args.output)
    try:
        # Start monitoring; if you want this to exit after a fixed time for testing, pass timeout value in seconds.
        monitor.start_monitoring(timeout=None)
    except KeyboardInterrupt:
        print("Packet capturing interrupted by user.")
    finally:
        monitor.close()


if __name__ == "__main__":
    main()
