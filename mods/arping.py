#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
sys.path.append("./libs")
from mixins import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


# arping module
class arping(GetMacsMixin):
	def __init__(self, params):
		if len(params) != 1:
			self.usage()
			exit(1)
		self.target = params[0]

	def usage(self):
		print "Usage:"
		print "\t%s ether.arping <target>" % sys.argv[0]

	def start(self):
		tab = self.getmacs(self.target)
		print 'IP: MAC'
		for ip in tab['ip_mac']:
			print " ", ip, tab['ip_mac'][ip]
		print 'MAC: IP'
		for mac in tab['mac_ip']:
			print " ", mac, " ".join(tab['mac_ip'][mac])

