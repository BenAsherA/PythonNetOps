import csv
import scapy.all as scapy

PACKETS=100

with open('protocols.csv', 'w', newline='') as csvfile:

    csvwriter = csv.writer(csvfile)

    def get_packet_protocol(packet_layers): # extracts the correct field to represent the protocol and returns it.
        if packet_layers[0] == 'Ether':
            if 'IP' in packet_layers[1]:
                return packet_layers[2]
            elif str(packet_layers[1]) == 'ARP':
                return packet_layers[1]
            else:
                return packet_layers[1]
        else:
            return packet_layers[0]

    def get_packet_layers(packet): # converts the osi layers in the packet object into a list of strings
        return [str(layer.__name__) for layer in packet.layers()]

    def write_packet(packet):
        packet_layers = get_packet_layers(packet)
        csvwriter.writerow([get_packet_protocol(packet_layers)])

    scapy.sniff(prn=write_packet, count=PACKETS, store=False)

    #the tasks: 1) start the sniff, call a function (write_packet) 2)open a csv file for writing data 3)extract the protocol from the packet. 4) write it to the csv