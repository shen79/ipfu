#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
sys.path.append("./libs")
from mixins import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress
scapy.conf.verb = 0

# udpholepunch
class udpholepunch(loggerMixin):
	def __init__(self, params):
		if len(params) != 4:
			self.usage()
			exit(1)
		self.proto = params[0]
		self.server_ip = params[1]
		self.client_ip = params[2]
		self.domain = params[3]

	def usage(self):
		print "Usage:"
		print "\t%s udpholepunch <proto:dns|53|snmp|161|time|123|?> <serverip> <clientip> <domain>" % sys.argv[0]

	def start(self):
		self.dnspunch(self.server_ip, self.client_ip, self.domain)
	
	def dnspunch(self, server, client, domain):
		# punchpkt
		self.msg("sending punchies...")
		pkt = scapy.IP(src=server, dst=client)
		pkt/= scapy.UDP(sport=53, dport=53)
		pkt/= scapy.Raw("udp holepunch test")
		scapy.send(pkt)

		# rqpkt
		self.msg("sending requests...")
		pkt = scapy.IP(src=client, dst=server)
		pkt/= scapy.UDP(sport=53, dport=53)
		pkt/= scapy.DNS(rd=1,qd=scapy.DNSQR(qname=domain))

		x = scapy.sr(pkt, timeout=5)
		print x[0]
		for p in x[0]:
			if p[1].proto == 1:
				print "%s %s/%s" %( p[1].sprintf("%IP.src%"), p[1].sprintf("%ICMP.type%"), p[1].sprintf("%ICMP.code%") )
			else:
				p[1].show()

