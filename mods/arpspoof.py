#!/usr/bin/python

import logging, signal,sys
from IPFU import *
from scapy import all as scapy
from netaddr import IPAddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0




class arpspoof(IPFU):
	"""TODO arpspoof - simple ARP spoof attack
	ipfu arpspoof <gateway> <target_ip|all>
	"""
	
	def __init__(self, params=None):
		signal.signal(signal.SIGINT, self.abort_attack)
		try:
			self.gateway = params[0]
			self.target = params[1]
			self.run = True
		except:
			print self.__doc__
			if params is not None: exit(1)

	def abort_attack(self, signal, frame):
		print("aborting attack")
		sys.exit(0)


	def start(self):
		pass
		while self.run:
			print 'xx'
			time.sleep(1)
			pass
		lt = self.getmacs(self.mynet)
		pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		pkt/= scapy.ARP(op=scapy.ARP.who_has, pdst=self.subnet)
		log.msg("Scanning...")
		a,u = scapy.srp(pkt, timeout=2, iface=self.iface)
		log.msg("Finished")
		for p in a:
#			p[1].show()
			a_mac = p[1].sprintf("%ARP.hwsrc%")
			a_ip = p[1].sprintf("%ARP.psrc%")
			try:
				t_ip = " ".join(lt["mac_ip"][a_mac])
			except:
				t_ip = 'unknown'
			log.msg("found: %17s %15s %s" % (a_mac, a_ip, t_ip))
















