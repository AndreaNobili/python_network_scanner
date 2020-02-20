#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP or an IP range")
    options = parser.parse_args()
    return options

def scan(ip):
    #scapy.arping(ip)

    # Create an object representing an ARP packet asking the MAC of the specific IP:
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()


    # Create an Ethernet frame to the broadcast MAC address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()

    # combination of the Ethernate frame and the ARP packet
    arp_request_broadcast = broadcast/arp_request
    #print(broadcast/arp_request)
    #arp_request_broadcast.show()

    # Send the request. It sends a packet with custom header.
    # Return 2 lists: list of answered packets and list of unanswered packets
    #answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1)

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # get only answered packets
    #print(answered_list.summary())
    #print(unanswered_list.summary())


    """
    element is a 'tuple' object. First member of the tuple is the packet sent, second one is the answer.
    - packet sent: it is always the same (sent to the broadcast MAC address but change the 
                   destination IP-
    - answer: contain the MAC address of the current IP.
                   
    """
    clients_list = []

    for element in answered_list:
        # print(type(element))
        # print(element[1].show()) # I am interested only in the answer, showing the fields
        """
        I am interested to retrieve only 2 fields: 
            - psrc (source IP retrieved from the ARP layer)
            - hwsrc (the MAC address retrieved from the ARP payer)
        """
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}

        clients_list.append(client_dict)

    return clients_list


def print_result(result_list):
    print("IP\t\t\t\tMAC Address\n-------------------------------------------------------")

    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


#scan_result = scan("192.168.223.2/24")

# Instead hard coding the network range to scan I obtain from the console using "command arguments":
options = get_arguments()
scan_result = scan(options.target)

print_result(scan_result)

