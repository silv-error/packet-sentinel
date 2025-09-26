import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from termcolor import colored

VERSION = "1.0"
AUTHOR = "silv"
DESCRIPTION = "Lightweight PoC IDS/IPS — block IPs by packets-per-second (pps)"
BANNER = rf"""

       /!_.-_|\
       `-/_'--'
       (_(o)\\\)
        (||\\\\;_,
         /  _-".----.
       ./_-"  /o,--.o\
      /      |o (  ) o|
     !__,--.__\o `-'o/
      |_-__--__`----'
     __,/\_|\/\, Packet Sentinel v{VERSION}
    (   `/_'`X_;
     `.____)____) 
     
            Author: {AUTHOR}
            Description: {DESCRIPTION}
"""

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]
    
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            print(f"IP: {ip}, Packet rate: {packet_rate}")  
            if packet_rate > threshold and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"netsh advfirewall firewall add rule name='Block_by_packet_sentinel' dir=in action=block remoteip={ip}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    print(colored(BANNER, "cyan"))
    threshold = int(input(colored("[?] Enter number of packets-per-second: ", "yellow")))
    print(f"THRESHOLD: {threshold}")   

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    try:
        sniff(filter="ip", prn=packet_callback)
    except Exception as e:
        print("An error occured:", e)
        sys.exit(1)
    except:
        print("Failed to start system...")
        sys.exit(1)