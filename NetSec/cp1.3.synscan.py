from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan

    ans, unans = sr(IP(dst=ip_addr) / TCP(dport=(1,1024), flags = 'S'), verbose=0, timeout=1)
	
    #ans.summary()

    flags = 0
    idx = 1
	
    for request, response in ans:
        if(response.getlayer(TCP).flags == 'SA'):
            sr(IP(dst=ip_addr) / TCP(dport=idx, flags = 'R'), verbose=0, timeout=1)
            flags = idx
        idx = idx+1

    print (str(ip_addr) + ',' + str(flags))

