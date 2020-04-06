#!usr/bin/env python3

'''
Run:
python3 scanner.py -t 192.168.1.1/24
'''

import scapy.all as sp
import argparse

def get_arg(flag, name, text):
    parser = argparse.ArgumentParser()
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    value = parser.parse_args()
    return value
def scan(ip):
    arp_req = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answered = sp.srp(arp_broadcast, timeout=10)[0]
    print("IP\t\t\t\tMAC")
    print("=================================================")
    for i in answered:
        print(i[1].psrc+"\t\t\t"+i[1].hwsrc)

ip = get_arg("t", "target", "The target IP/IPs that you want to scan")
if(ip.target):
    scan(ip.target)
else:
    print("Please specify the target, --help for more details")
