#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *
from scapy import all as scapy
from netaddr import IPAddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0



# rr module
class rr(IPFU):
	"""rr - Record Route IP options feature using ICMP and TCP
	ipfu rr <IP> <tcpport>
	"""
	def __init__(self, params=None):
		self.do_icmp = False
		try:
			self.dst = params[0]
			self.dport = params[1]
		except:		
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		icmprr = self.rr_icmp(self.dst)
		self.msg("icmp route: %s" % icmprr)
		tcprr = self.rr_tcp(self.dst, self.dport)
		self.msg("tcp route: %s" % tcprr)

	def rr_icmp(self, dst):
		pkt = scapy.IP(dst=dst, proto=1, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt /= scapy.ICMP()
		intr_icmp = scapy.sr1(pkt, timeout=2)
		if intr_icmp is not '':
			try:
				return intr_icmp.options[0].routers
			except:
				return None

	def rr_tcp(self, dst, dport):
		pkt = scapy.IP(dst=dst, proto=6, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt/= scapy.TCP(sport=scapy.RandNum(1024,65535), dport=int(dport), flags="S",window=8192,
				options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None),
					 ('NOP', None), ('SAckOK', '')])
		intr_tcp = scapy.sr1(pkt, timeout=2)
		if intr_tcp is not None:
			return intr_tcp.options[0].routers

