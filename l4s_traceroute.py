import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress interface warnings
from scapy.config import conf
from scapy.sendrecv import sr
from scapy.utils import do_graph, incremental_label, colgen
from scapy.volatile import RandShort, RandInt
from scapy.layers.inet import TracerouteResult, IP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded

def node_colgen(bleach_tuple):
  total = bleach_tuple[0]
  preserve = bleach_tuple[1]
  default_col = "#32CD32"
  step_size = 75 # TODO: Play around with code; Need to calculate per total -- otherwise gradient will be static ; non-proportional (node w/ many connections may show up as very white while node w/ few connections show up as green or vice versa)
  offset = total - preserve
  rgb_hex = [default_col[x:x+2] for x in [1, 3, 5]]
  new_rgb_int = [int(hex_value, 16) + (offset * step_size) for hex_value in rgb_hex]
  new_rgb_int = [min([255, max([0, i])]) for i in new_rgb_int]
  return '#%02x%02x%02x' % tuple(new_rgb_int)

def graph(tr_res, mark_dict):
  ASres = conf.AS_resolver
  padding = 0
  ips = {}
  rt = {}
  ports = {}
  ports_done = {}
  for s, r in tr_res:
    r = r.getlayer(IP) or (conf.ipv6_enabled and r[scapy.layers.inet6.IPv6]) or r  # noqa: E501
    s = s.getlayer(IP) or (conf.ipv6_enabled and s[scapy.layers.inet6.IPv6]) or s  # noqa: E501
    ips[r.src] = None
    if TCP in s:
      trace_id = (s.src, s.dst, 6, s.dport)
    elif UDP in s:
      trace_id = (s.src, s.dst, 17, s.dport)
    elif ICMP in s:
      trace_id = (s.src, s.dst, 1, s.type)
    else:
      trace_id = (s.src, s.dst, s.proto, 0)
    trace = rt.get(trace_id, {})
    ttl = conf.ipv6_enabled and IPv6 in s and s.hlim or s.ttl  # noqa: E501
    if not (ICMP in r and r[ICMP].type == 11) and not (conf.ipv6_enabled and IPv6 in r and ICMPv6TimeExceeded in r):  # noqa: E501
      if trace_id in ports_done:
        continue
      ports_done[trace_id] = None
      p = ports.get(r.src, [])
      if TCP in r:
        p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))  # noqa: E501
        trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
      elif UDP in r:
        p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
        trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
      elif ICMP in r:
        p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
        trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
      else:
        p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))  # noqa: E501
        trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')  # noqa: E501
      ports[r.src] = p
    else:
      trace[ttl] = r.sprintf('"%r,src%"')
    rt[trace_id] = trace

  # Fill holes with unk%i nodes
  unknown_label = incremental_label("unk%i")
  blackholes = []
  bhip = {}
  for rtk in rt:
    trace = rt[rtk]
    max_trace = max(trace)
    for n in range(min(trace), max_trace):
      if n not in trace:
        trace[n] = next(unknown_label)
    if rtk not in ports_done:
      if rtk[2] == 1:  # ICMP
        bh = "%s %i/icmp" % (rtk[1], rtk[3])
      elif rtk[2] == 6:  # TCP
        bh = "%s %i/tcp" % (rtk[1], rtk[3])
      elif rtk[2] == 17:  # UDP
        bh = '%s %i/udp' % (rtk[1], rtk[3])
      else:
        bh = '%s %i/proto' % (rtk[1], rtk[2])
      ips[bh] = None
      bhip[rtk[1]] = bh
      bh = '"%s"' % bh
      trace[max_trace + 1] = bh
      blackholes.append(bh)

  # Find AS numbers
  ASN_query_list = set(x.rsplit(" ", 1)[0] for x in ips)
  if ASres is None:
    ASNlist = []
  else:
    ASNlist = ASres.resolve(*ASN_query_list)

  ASNs = {}
  ASDs = {}
  for ip, asn, desc, in ASNlist:
    if asn is None:
      continue
    iplist = ASNs.get(asn, [])
    if ip in bhip:
      if ip in ports:
        iplist.append(ip)
      iplist.append(bhip[ip])
    else:
      iplist.append(ip)
    ASNs[asn] = iplist
    ASDs[asn] = desc

  backcolorlist = colgen("60", "86", "ba", "ff")
  forecolorlist = colgen("a0", "70", "40", "20")

  s = "digraph trace {\n"

  s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"

  s += "\n#ASN clustering\n"
  for asn in ASNs:
    s += '\tsubgraph cluster_%s {\n' % asn
    col = next(backcolorlist)
    s += '\t\tcolor="#%s%s%s";' % col
    s += '\t\tpenwidth=2.5;'
    s += '\t\tnode [style=filled];'
    s += '\t\tfontsize=10;'
    s += '\t\tlabel = "%s\\n[%s]";\n' % (asn, ASDs[asn])
    for ip in ASNs[asn]:
      n_col = node_colgen(mark_dict[ip])
      s += '\t\tnode[fillcolor="%s"] "%s";\n' % (n_col, ip)
    s += "\t}\n"

  s += "#endpoints\n"
  for p in ports:
    s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p, p, "|".join(ports[p]))  # noqa: E501

  s += "\n#Blackholes\n"
  for bh in blackholes:
    s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh  # noqa: E501

  if padding:
    s += "\n#Padding\n"
    pad = {}
    for snd, rcv in tr_res:
      if rcv.src not in ports and rcv.haslayer(conf.padding_layer):
        p = rcv.getlayer(conf.padding_layer).load
        if p != b"\x00" * len(p):
          pad[rcv.src] = None
    for rcv in pad:
      s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv  # noqa: E501

  s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"

  for rtk in rt:
    s += "#---[%s\n" % repr(rtk)
    s += '\t\tedge [color="#%s%s%s"];\n' % next(forecolorlist)
    trace = rt[rtk]
    maxtrace = max(trace)
    for n in range(min(trace), maxtrace):
      s += '\t%s ->\n' % trace[n]
    s += '\t%s;\n' % trace[maxtrace]

  s += "}\n"

  return s

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
  mark_dict = {}
  if isinstance(target, str):
    print("traceroute to {} ({}), maxttl {} seconds".format(target, socket.gethostbyname(target), maxttl))
  else:
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
    request = hop[0]
    response = hop[1] # Class IP
    try:
      host = socket.gethostbyaddr(response.src)[0]
    except:
      host = response.src
    # Check if router bleached ECN bits, and update times this router has been pinged/bleach count
      # (num. times pinged, num. preservations of ecn bits)
    # If bleached
    if response.tos & 0x3 != 2 or response.tos & 0x3 != 3:
      if response.src in mark_dict:
        mark_dict[response.src][0] += 1
      else:
        mark_dict[response.src] = [1, 0]
    # If not bleached
    else:
      if response.src in mark_dict:
        mark_dict[response.src][0] += 1
        mark_dict[response.src][1] += 1
      else:
        mark_dict[response.src] = [1, 1]

    print("{}\t{} ({}) {} ms, tos={}, ecn={}".format(count, host, response.src, '%.3f'%((response.time - request.sent_time)*1000), str(f"{response.tos:b}"), str(f"{response.tos & 0x3:b}")))
    count += 1

  a = TracerouteResult(a.res)
  if verbose:
    a.show()
  return a, b, mark_dict

def main():
  res, unans, mark_dict = traceroute(["google.com", "youtube.com"], verbose=0) #: verbosity, from 0 (almost mute) to 3 (verbose)
  s = graph(res, mark_dict)
  do_graph(s, target="> /tmp/graph.svg")
  # res.graph(target="> /tmp/graph.svg")

main()