# 34.200.129.209 -- UC
# 157.240.22.35 -- FB

from scapy.all import *

sport = random.randint(1024,65535)

# SYN
ip=IP(src='10.150.133.150',dst='34.200.129.209')
SYN=TCP(sport=sport,dport=443,flags='SEC',seq=1000) #set the SYN, CWR and ECE flags on

SYN.sprintf('%TCP.flags%')
SYNACK=sr(ip/SYN, iface = 'en0')[0]

# If the ECE bit is turned on along with the SYN ACK, then the website supports ECN.
print(SYNACK.show())

## Conditional for above, if so, measure L4S packet and non-L4S, see with n packets, if there's a difference in timings