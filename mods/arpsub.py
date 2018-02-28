#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
sys.path.append("./libs")
from mixins import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0




class arpsub(GetMacsMixin):
	def __init__(self, params):
		if len(params) != 3:
			self.usage()
			exit(1)
		self.iface = params[0]
		self.mynet = params[1]
#		self.myip = params[2]
		self.subnet = params[2]

	def usage(self):
		print "Usage: %s ether.arpsub <iface> <your-network> <your-ip> <subnet>" % sys.argv[0]

	def start(self):
		lt = self.getmacs(self.mynet)
		
		pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#		pkt/= scapy.ARP(op=scapy.ARP.who_has, psrc=self.myip, pdst=self.subnet)
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
















