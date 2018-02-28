#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


class lvsdetect(IPFU):
	"""lvsdetect
	ipfu lvsdetect <IP> <tcpport> <packets#> <tolerance>
	"""
	def __init__(self, params=None):
		try:
			self.do_icmp = False
			self.dst = params[0]
			self.dport = int(params[1])
			self.mpackets = int(params[2])
			self.tolerance = int(params[3])
			self.sport = scapy.RandNum(1024,65535)
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		pkts = self.m1(self.dst, self.dport)
		ipids = []
		for p in pkts:
			ipids.append(p[1].id)
		ipids.sort()
		self.msg("IPIDS: %s" % ipids)
		pits = 1
		prev = -1
		groups = {}
		groups[pits] = []
		self.msg("guessing number of backends (patterns=%d, tolerance=%d)" % (self.mpackets, self.tolerance))
		for ipid in ipids:
#			log.msg("ipid: (%d) %d" % (prev, ipid))
			if prev > 0:
				#log.msg("+ dif: %d" % (ipid-prev))
				if (ipid-prev) > self.tolerance:
#					log.msg("JUMP: %d" % (ipid-prev))
					pits += 1
					groups[pits] = []
				if not pits in groups:
					groups[pits] = []
			groups[pits].append(ipid)
			prev = ipid
		self.msg("guess: %d" % pits)
		total = len(ipids)
		self.msg("total response: %d" % total)
		for g in groups:
			num = len(groups[g])
			percent = float(100) / float(total) * float(num)
			self.msg("S#%-2d %d/%d %.2f%%: %s" % (g, num, total, percent, groups[g]))
					
			

	def m1(self, dst, dport):
		pkt = scapy.IP(dst=dst)
		pkt/= scapy.TCP(sport=self.sport, dport=dport, flags="S", window=8192,
				options=[
					('MSS', 1460),
					('NOP', None),
					('WScale', 2),
					('NOP', None),
					('NOP', None),
					('SAckOK', '')
				])
		a,u = scapy.sr(pkt * self.mpackets, timeout=2)
		if a is not None:
			return a

