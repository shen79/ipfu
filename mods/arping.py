#!/usr/bin/python

import logging
from IPFU import *
from scapy import all as scapy
from netaddr import IPAddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0


# arping module
class arping(IPFU):
	"""arping - creates Mac-IP/IP-MAC mapping 
	ipfu arping <ip2mac|mac2ip|all> <target_network>
	"""
	def __init__(self, params=None):
		try:
			self.req = params[0]
			self.target = params[1]
		except:
			print self.__doc__
			if params is not None: exit(1)

	def mac2ip(self):
		for mac in self.tab['mac_ip']:
			print mac, " ".join(self.tab['mac_ip'][mac])

	def ip2mac(self):
		for ip in self.tab['ip_mac']:
			print ip, self.tab['ip_mac'][ip]

	def start(self):
		self.tab = self.getmacs(self.target)
		if self.req == 'ip2mac': self.mac2ip()
		elif self.req == 'mac2ip': self.ip2mac()
		elif self.req == 'all':
			print '=== IP2MAC'
			self.ip2mac()
			print '=== MAC2IP'
			self.mac2ip()

