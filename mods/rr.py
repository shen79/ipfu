#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
sys.path.append("./libs")
from mixins import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0



# rr module
class rr(loggerMixin):
	def __init__(self, params):
		self.do_icmp = False

		textparams = filter(lambda x: x != "-i", params)
		if len(textparams) < 2:
			self.usage()
			exit(1)

		if "-i" in params:
			self.do_icmp=True

		self.dst = textparams[0]
		self.dport = textparams[1]

	def usage(self):
		print "Usage: %s ip.rr [-i] <IP> <tcpport>" % sys.argv[0]
		print "\t -i\tdo ICMP RR"

	def start(self):
		if self.do_icmp == 1:
			icmprr = self.rr_icmp(self.dst)
			slef.msg("icmp route: %s" % icmprr)
		tcprr = self.rr_tcp(self.dst, self.dport)
		self.msg("tcp route: %s" % tcprr)

	def rr_icmp(self, dst):
		pkt = scapy.IP(dst=dst, proto=1, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt /= scapy.ICMP()
		intr_icmp = scapy.sr1(pkt, timeout=2)
		if intr_icmp is not '':
			return intr_icmp.options[0].routers

	def rr_tcp(self, dst, dport):
		pkt = scapy.IP(dst=dst, proto=6, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt/= scapy.TCP(sport=scapy.RandNum(1024,65535), dport=int(dport), flags="S",window=8192,
				options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None),
					 ('NOP', None), ('SAckOK', '')])
		intr_tcp = scapy.sr1(pkt, timeout=2)
		if intr_tcp is not None:
			return intr_tcp.options[0].routers

