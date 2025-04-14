import csv
import scapy.all as scapy

packets=100

with open('protocols.csv','w',newline='') as csvfile: # opens the csv file, and will close it at the end of the block

    csvwriter = csv.writer(csvfile) # creating a writer object for our csv file
    def writepacket(packet): # will be called by the scapy.sniff function for each packet. This function does the categorizing we want, and writes the data into our csv file

        osi = [str(layer.__name__) for layer in packet.layers()] # converting the layers in the packet object into a list of strings

        #extract the correct field to represent the protocol and write it into the csv file.
        if str(osi[0]) == 'Ether':
            if 'IP' in osi[1]:
                csvwriter.writerow([osi[2]])
            elif str(osi[1]) == 'ARP':
                csvwriter.writerow([osi[1]])
            else:
                csvwriter.writerow([osi[1]])
        else:
            csvwriter.writerow([osi[0]])


    scapy.sniff(prn=writepacket, count=packets, store=False) #sniffs packets according to the amount we set in 'packets'


    #the tasks: 1) start the sniff, call a function (writepacket) 2)open a csv file for writing data 3)extract the protocol from the packet 4) write it to the csv and flush it