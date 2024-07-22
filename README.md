# edr_blocker
Blocks EDR Telemetry by conducting Man-in-the-Middle attack where network filtering is applied based on the ables the SNI in the TLS Client Hello packet.

```
# python3 edr_blocker.py -h

 ______   _____    ______       ______   __       ______   ______   __  __   ______   ______
/\  ___\ /\  __-. /\  == \     /\  == \ /\ \     /\  __ \ /\  ___\ /\ \/ /  /\  ___\ /\  == \
\ \  __\ \ \ \/\ \\ \  __<     \ \  __< \ \ \____\ \ \/\ \\ \ \____\ \  _"-.\ \  __\ \ \  __<
 \ \_____\\ \____- \ \_\ \_\    \ \_____\\ \_____\\ \_____\\ \_____\\ \_\ \_\\ \_____\\ \_\ \_\
  \/_____/ \/____/  \/_/ /_/     \/_____/ \/_____/ \/_____/ \/_____/ \/_/\/_/ \/_____/ \/_/ /_/

                                                            by Tier Zero Security - New Zealand

usage: edr_blocker.py [-h] -i INTERFACE -f FILE [-m] [-v] -t TARGET -gw GATEWAY

Sniff TLS Client Hello packets and block specified domains.

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to sniff on
  -f FILE, --file FILE  File containing the list of blocked domains
  -m, --monitor         Monitor mode: only detect and log blocked IPs, do not add iptables rules
  -v, --verbose         Enable verbose output
  -t TARGET, --target TARGET
                        Target IP address or range (e.g., 192.168.0.1-10 or 192.168.0.1,192.168.0.2 (no space)
  -gw GATEWAY, --gateway GATEWAY
                        Gateway IP address
```
