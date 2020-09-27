# coding=utf-8

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
from termcolor import colored
import time

ssidlist, info_list, info_list_2 = [], [], []

banner = """
         WiFi Pineapple Activity Analysis
          Same SSID Different Encryption
"""

def air_scan(pkt):
    if pkt.haslayer(Dot11Beacon):
       ssid, bssid = pkt.info, pkt.addr2
       if ssid not in ssidlist and len(ssid)!=0:
           ssidlist.append(ssid)
       capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                                                  {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
       enc = "Y"
       if "privacy" not in capability and len(ssid)!=0:
          enc = 'N'
          info = enc+"**"+ssid
          if info not in info_list and info_list_2:
             info_list.append(info)
       elif "privacy" in capability and len(ssid)!=0:
          info = enc+"**"+ssid
          if info not in info_list_2:
             info_list_2.append(info)


if __name__ == '__main__':
    print banner
    print "[+] Reading pcap file: pineapple.pcap ..."
    logs = rdpcap("pineapple.pcap")
    print "[+] Total packets: ", len(logs)
    for pkt in logs:
        air_scan(pkt)
    print "[+] Founded ", len(info_list), " UnEncrypted WiFi"
    time.sleep(3)
    print "[+] Founded ", len(info_list_2), " **Encrypted WiFi"
    time.sleep(3)
    print "[+] [Pineapple] - Packet Analysis for WiFi Pineapple Activities"
    print "\n------------------------------"
    for un in info_list:
        for i in info_list_2:
            ssid_2 = i.split("**")[1]
            if ssid_2 in un:
                print "[DEBUG] Same SSID and Different encryption: ", ssid_2
