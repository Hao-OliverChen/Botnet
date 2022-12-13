# from scapy.all import *
# import time

# # Define the port to monitor
# port = 8266

# while True:
#   # Use Scapy's sniff() function to capture packets on the specified port
#   packets = sniff(filter="port {}".format(port), count=10)
  
#   # Loop through the packets and print the relevant information
#   for packet in packets:
#     print("Source IP:", packet[IP].src)
#     print("Destination IP:", packet[IP].dst)
#     print("Protocol:", packet[IP].proto)
#     print("Payload:", packet[IP].payload)
#     print("------------------------------")
  
#   # Sleep for 15 seconds before capturing the next batch of packets
#   time.sleep(1)

#------------------------------------------------------------------------------------------------------

# import scapy.all as scapy
# import time

# a = 0
# while True:
#     a = a+1
#     msg = "Batch: %d"
#     print(msg % a)
#     print("")
#     request = scapy.ARP()
#     request.pdst = '10.64.18.2'
#     broadcast = scapy.Ether()
#     broadcast.dst = 'ff:ff:ff:ff:ff:ff'
#     request_broadcast = broadcast / request
#     clients = scapy.srp(request_broadcast, timeout = 1)[0]
#     for element in clients:
#         print(element[1].psrc + "      " + element[1].hwsrc)
#     print(request.summary())
#     print("----------------------------------")
#     time.sleep(1)

#------------------------------------------------------------------------------------------------------

# from collections import Counter
# from scapy.all import sniff

# ## Create a Packet Counter
# packet_counts = Counter()

# ## Define our Custom Action function
# def custom_action(packet):
#     # Create tuple of Src/Dst in sorted order
#     key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
#     packet_counts.update([key])
#     return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

# ## Setup sniff, filtering for IP traffic
# sniff(filter="ip", prn=custom_action, count=10)

# ## Print out packet count per A <--> Z address pair
# print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))

#------------------------------------------------------------------------------------------------

# # Import the scapy library
# from scapy.all import *

# # Define the function to be called for each packet
# def packet_info(pkt):
#     # Print the packet's source and destination
#     print("Source: " + pkt[IP].src)
#     print("Destination: " + pkt[IP].dst)

#     # Check if the packet has an ending destination (i.e. if it's not the final destination)
#     if pkt.haslayer(IP):
#         # If the packet has an ending destination, print it
#         print("Ending Destination: " + pkt[IP].dst)

# # Use the sniff function to capture all packets on all ports from IP address 10.64.18.1
# sniff(filter="src 10.64.18.2 and portrange 30000-40000", prn=packet_info)

#--------------------------------------------------------------------------------------------------------

# from scapy.all import *
# from datetime import datetime

# class ids:
#     __flagsTCP = {
#         'F': 'FIN',
#         'S': 'SYN',
#         'R': 'RST',
#         'P': 'PSH',
#         'A': 'ACK',
#         'U': 'URG',
#         'E': 'ECE',
#         'C': 'CWR',
#         }

#     __ip_cnt_TCP = {}               #ip address requests counter

#     __THRESH=1000               

#     def sniffPackets(self,packet):
#         if packet.haslayer(IP):
#             pckt_src=packet[IP].src
#             pckt_dst=packet[IP].dst
#             print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

#         if packet.haslayer(TCP):
#             src_port=packet.sport
#             dst_port=packet.dport
#             print(", Port: %s --> %s, "%(src_port,dst_port), end='')
#             print([type(self).__flagsTCP[x] for x in packet.sprintf('%TCP.flags%')])
#             self.detect_TCPflood(packet)
#         else:
#             print()


#     def detect_TCPflood(self,packet):
#         if packet.haslayer(TCP):
#             pckt_src=packet[IP].src
#             pckt_dst=packet[IP].dst
#             stream = pckt_src + ':' + pckt_dst

#             if stream in type(self).__ip_cnt_TCP:
#                 type(self).__ip_cnt_TCP[stream] += 1
#             else:
#                 type(self).__ip_cnt_TCP[stream] = 1

#             for stream in type(self).__ip_cnt_TCP:
#                 pckts_sent = type(self).__ip_cnt_TCP[stream]
#                 if pckts_sent > type(self).__THRESH:
#                     src = stream.split(':')[0]
#                     dst = stream.split(':')[1]
#                     print("Possible Flooding Attack from %s --> %s"%(src,dst))


# if __name__ == '__main__':
#     print("custom packet sniffer ")
#     sniff(prn=ids().sniffPackets)

