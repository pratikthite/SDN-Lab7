#! /usr/bin/env python3

import threading
import subprocess
import os
from scapy.all import *
from scapy.contrib.openflow3 import *

class count_packetIn:
    def __init__(self, port, interface = "enp0s3"):
        self.port = port
        self.interface = interface
        self.count_dict = {}
        self.ipt_list = []
    
    def configure_iptables(self, src_ip, src_port, dst_port):
        rule = "iptables -A INPUT -p tcp --source-port %s --destination-port %s -s %s -j DROP" % (src_port, dst_port, src_ip)
        if rule not in self.ipt_list:
            ipt = os.system(rule)
            self.ipt_list.append(rule)
        #output1 = subprocess.check_output('sudo iptables -L -n -v | head -3 | tail -1', shell=True, text=True)
        
    def custom_action(self, packet):
        src_ip = packet['IP'].src
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        t1 = (src_ip, src_port)
        if OFPTPacketIn in packet:
            print(t1)
            if t1 in self.count_dict:
                count = self.count_dict[t1]
                count += 1
                self.count_dict[t1] = count
                print(self.count_dict)
                if self.count_dict[t1] > 100:
                    self.configure_iptables(src_ip, src_port, dst_port)
            else:
                self.count_dict[t1] = 1

    def sniff_packet_in(self):
        sniff(filter='port '+str(self.port), prn=self.custom_action, iface=self.interface, timeout=45)

def main():
    monitor_obj = count_packetIn('6653')
    monitor_obj.sniff_packet_in()
    output1 = subprocess.check_output('sudo iptables -L -n -v | head -3 | tail -1', shell=True)
    print(output1)

if __name__ == "__main__":
    main()
