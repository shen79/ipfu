#!/usr/bin/python

from IPFU import *

import logging
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
			self.command = params[0]
			self.target = params[1]
		except:
			print self.__doc__
			if params is not None: exit(1)

	def mac2ip(self):
		for mac in self.address_table['mac_ip']:
			print mac, " ".join(self.address_table['mac_ip'][mac])

	def ip2mac(self):
		for ip in self.address_table['ip_mac']:
			print ip, self.address_table['ip_mac'][ip]

	def start(self):
		self.address_table = self.getmacs(self.target)
		if self.command == 'ip2mac':
			# TODO: sort
			print '=== IP2MAC'
			self.mac2ip()
		elif self.command == 'mac2ip':
			print '=== MAC2IP'
			self.ip2mac()
		elif self.command == 'all':
			print '=== IP2MAC'
			self.ip2mac()
			print '=== MAC2IP'
			self.mac2ip()
