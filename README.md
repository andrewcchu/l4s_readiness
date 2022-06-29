# L4S Traceroute

### Files

`l4s_traceroute.py` -- modifed version of scapy traceroute that additionally has functions to check ECN compliance, and L4S compliance (pending).

`default_check.py` -- performs default TCP traceroute provided by [scapy](https://scapy.net/) as demonstrated [here](https://scapy.readthedocs.io/en/latest/usage.html#tcp-traceroute).

### Dependencies

#### Packages
Install with `pip3 install -r REQUIREMENTS.txt`.
* [scapy](https://scapy.net/)

#### Non-package Dependencies
Follow the instructions here for your respsective OS.
* [graphviz](https://graphviz.org/download/)

### Usage

#### l4s_traceroute.py:

Before running:
1. Change the figure save location in `l4s_traceroute.py:393` to your appropriate path
2. Change the last argument in `traceroute:390` to one of `ecn_ip=1`, `ecn_tcp=1`, or `accEcn=1` to run the respective function
  * `ecn_ip=1` will check if the ECN bits (two least significant bits in ToS field, IP header) are preserved in reply
  * `ecn_tcp=1` will check if a host replies with TCP flags signifying that ECN is supported
  * `accEcn=1` will check if the host replies with TCP flags signifying that L4S is supported (based off of N --> AE flag in [TCP Prague](https://www.bobbriscoe.net/projects/latency/tcp-prague-netdev0x13.pdf), top right col., page 5)  
3. Change/modify the sites to perform traceroute to in the variable `sites`

#### default_check.py:

Before running:
1. Change the figure save location to your appropriate path
2. Change/modify the sites to perform traceroute to in the variable `sites`
