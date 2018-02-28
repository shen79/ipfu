#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *
import pprint
from scapy import all as scapy
from netaddr import IPAddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0

# udpholepunch
class tracemap(IPFU):
	"""tracemap - traceroute to map
	ipfu tracemap <target> <proto:icmp|tcp|udp> [port]
	"""
	def __init__(self, params=None):
		try:
			self.target = params[0]
			self.proto = params[1]
			if self.proto in ["tcp", "udp"]:
				self.port = params[2]
			elif self.proto == "icmp":
				pass
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		self.tracemap()
	
	def tracemap(self):
		# punchpkt
		self.msg("tracemapping...")
		res = {}
		lasthop=32
#		ttls = range(0,lasthop+1)[::-1]
		packets = []
		for ttl in range(0,lasthop+1)[::-1]:
#			self.msg("ttl = %d" % ttl)
			pkt = scapy.IP(dst=self.target, ttl=ttl, id=ttl)
			if self.proto == "tcp":			pkt/= scapy.TCP(sport=12345, dport=self.port, flags="S")
			elif self.proto == "udp":		pkt/= scapy.UDP(sport=12345, dport=self.port)
			elif self.proto == "icmp":		pkt/= scapy.ICMP() / scapy.Raw(chr(ttl))
			else:
				self.usage()
				sys.exit(1)
			packets.append(pkt)
		res = scapy.sr(packets, timeout=4, inter=0.2)
	
#		print res
	
		trace = {}
		for pkt in res[0]:
			p = pkt[1]
			if p.sprintf("%IP.proto%") == "icmp":
				tc = p.sprintf("%ICMP.type%:%ICMP.code%")
				if tc == "time-exceeded:ttl-zero-during-transit":
					srcip = p.sprintf("%IP.src%")
					dstip = p.sprintf("%ICMP.dst%")
					ttl = p.getlayer(2).sprintf("%id%")
					if dstip not in trace:
						trace[dstip] = {}
					trace[dstip][int(ttl)] = srcip
				elif tc == "echo-reply:0":
					srcip = p.sprintf("%IP.src%")
					ttl = ord(p["Raw"].load)
					if srcip not in trace:
						trace[srcip] = {}
					trace[srcip][int(ttl)] = [srcip, tc]
				else:
					p.show()
			elif p.sprintf("%IP.proto%") == "tcp":
				pass
			elif p.sprintf("%IP.proto%") == "udp":
				pass
		pprint.pprint(trace)
					
		





#	print "%s %s/%s" %( p[1].sprintf("%IP.src%"), p[1].sprintf("%ICMP.type%"), p[1].sprintf("%ICMP.code%") )

