#!/usr/bin/env python3
"""
Simple port analyzer that captures packets and exports port information to a CSV file.
"""

import sys
import csv
import argparse
from datetime import datetime

try:
    import scapy.all as scapy
except ImportError:
    print("This script requires scapy. Install it with: pip install scapy")
    sys.exit(1)


def analyze_packets(interface=None, output_file="ports.csv", count=None, timeout=None):
    """Capture packets and record port information to a CSV file"""
    # Prepare CSV file
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port'])

        print(f"Starting packet capture on interface: {interface or 'default'}")
        print(f"Recording port data to {output_file}")
        print("Press Ctrl+C to stop...")

        # Define packet callback
        def packet_callback(packet):
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

                # TCP packet
                if packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    csv_writer.writerow([timestamp, 'TCP', src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport])
                    csvfile.flush()  # Ensure data is written immediately

                # UDP packet
                elif packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    csv_writer.writerow([timestamp, 'UDP', src_ip, udp_layer.sport, dst_ip, udp_layer.dport])
                    csvfile.flush()

        # Start capture
        try:
            scapy.sniff(iface=interface, prn=packet_callback, count=count, timeout=timeout, store=0)
        except KeyboardInterrupt:
            print("\nStopping packet capture...")
        except Exception as e:
            print(f"Error during packet capture: {e}")


def main():
    parser = argparse.ArgumentParser(description="Capture network packets and export port information to CSV")
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    parser.add_argument("-o", "--output", default="ports.csv", help="Output CSV file (default: ports.csv)")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-t", "--timeout", type=int, help="Timeout for packet capture (seconds)")
    args = parser.parse_args()

    analyze_packets(
        interface=args.interface,
        output_file=args.output,
        count=args.count,
        timeout=args.timeout
    )

    print(f"Port data saved to {args.output}")
