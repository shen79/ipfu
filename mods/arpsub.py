#!/usr/bin/python

import logging
#, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0




class arpsub(IPFU):
	"""arpsub - ARP scan to find hosts connected to different networks / having different IP addresses
	ipfu arpsub <iface>  <subnet> [your-network]
		iface: your interface
		subnet: a different subnet you are interested in
		your-network: most possibly your net/netmask
	"""
	def __init__(self, params=None):
		try:
			self.iface = params[0]
			self.subnet = params[1]
			try:
				self.mynet = params[2]
			except:
				self.mynet = self.getMyNet(self.iface)
		except:
			print self.__doc__
			if params is not None: exit(1)
			
	def start(self):
		lt = self.getmacs(self.mynet)
		pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#		pkt/= scapy.ARP(op=scapy.ARP.who_has, psrc=self.myip, pdst=self.subnet)
		pkt/= scapy.ARP(op=scapy.ARP.who_has, pdst=self.subnet)
		self.msg("Scanning...")
		a,u = scapy.srp(pkt, timeout=2, iface=self.iface)
		self.msg("Finished")
		self.msg("       %-17s %-16s %s" % ('MAC address', 'local IP', 'extra IP'))
		for p in a:
#			p[1].show()
			a_mac = p[1].sprintf("%ARP.hwsrc%")
			a_ip = p[1].sprintf("%ARP.psrc%")
			try:
				t_ip = " ".join(lt["mac_ip"][a_mac])
			except:
				t_ip = 'unknown'
			self.msg("found: %-17s %-16s %s" % (a_mac, t_ip, a_ip))
















