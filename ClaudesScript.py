import scapy.all as scapy
import csv

output_file="ports.csv"
interface='eth0'
count=100
with open(output_file, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port'])

    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # TCP packet
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                csv_writer.writerow(['TCP', src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport])
                csvfile.flush() # saves the data from memory to the disk

            # UDP packet
            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                csv_writer.writerow(['UDP', src_ip, udp_layer.sport, dst_ip, udp_layer.dport])
                csvfile.flush()

    # Start packet capture
    scapy.sniff(iface=interface, prn=packet_callback, count=count, store=0)