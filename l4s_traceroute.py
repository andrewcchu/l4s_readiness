import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress interface warnings
from scapy.config import conf
from scapy.sendrecv import sr
from scapy.volatile import RandShort, RandInt
from scapy.layers.inet import TracerouteResult, IP, TCP

def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4=None, filter=None, timeout=2, verbose=None, **kargs):  # noqa: E501
  """Instant TCP traceroute
     :param target:  hostnames or IP addresses
     :param dport:   TCP destination port (default is 80)
     :param minttl:  minimum TTL (default is 1)
     :param maxttl:  maximum TTL (default is 30)
     :param sport:   TCP source port (default is random)
     :param l4:      use a Scapy packet instead of TCP
     :param filter:  BPF filter applied to received packets
     :param timeout: time to wait for answers (default is 2s)
     :param verbose: detailed output
     :return: an TracerouteResult, and a list of unanswered packets"""
  print("traceroute to {} ({}), maxttl {} seconds".format(", ".join(target), ", ".join(socket.gethostbyname(t) for t in target), maxttl))
  if verbose is None:
    verbose = conf.verb
  if filter is None:
    # we only consider ICMP error packets and TCP packets with at
    # least the ACK flag set *and* either the SYN or the RST flag
    # set
    filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"  # noqa: E501
  if l4 is None:
    # set tos=2 to represent a sender that wishes a packet to receive L4S treatment (https://datatracker.ietf.org/doc/html/draft-ietf-tsvwg-ecn-l4s-id#section-4.1)
    a, b = sr(IP(dst=target, id=RandShort(), ttl=(minttl, maxttl), tos=2) / TCP(seq=RandInt(), sport=sport, dport=dport),  # noqa: E501
          timeout=timeout, filter=filter, verbose=verbose, **kargs)
  else:
    # this should always work
    filter = "ip"
    a, b = sr(IP(dst=target, id=RandShort(), ttl=(minttl, maxttl), tos=2) / l4,
          timeout=timeout, filter=filter, verbose=verbose, **kargs)

  # a is SndRcvList, containing query/response packet tuples
  count = 0
  for hop in a:
    response = hop[1] # Class IP
    try:
      host = socket.gethostbyaddr(response.src)[0]
    except:
      host = response.src
    print("{}\t{} ({}), tos={}, ecn={}".format(count, host, response.src, response.tos, str(f"{response.tos & 0x3:b}")))
    count += 1

  a = TracerouteResult(a.res)
  if verbose:
    a.show()
  return a, b

def main():
  res, unans = traceroute(["www.yahoo.com","www.altavista.com","www.wisenut.com","www.copernic.com"], verbose=0) #: verbosity, from 0 (almost mute) to 3 (verbose)

main()