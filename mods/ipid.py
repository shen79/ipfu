#!/usr/bin/python

import logging, sys
from IPFU import *
from scapy import all as scapy
from netaddr import IPAddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0


class ipid(IPFU):
	"""ipid - IP.ID field measuring tool
	ipfu lvsdetect <IP> <tcpport> <packets> <tolerance>
	"""
	# https://tools.ietf.org/html/rfc6864
	def __init__(self, params=None):
		try:
			self.dst = params[0]
			self.dport = int(params[1])
			self.mpackets = int(params[2])
			self.tolerance = int(params[3])
			self.sport = scapy.RandNum(1024,65535)
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		pkts = self.send(self.dst, self.dport)
		ipids = []
		allnull = True
		for p in pkts:
			ipids.append(p[1].id)
			if p[1].id > 0:
				allnull = False
		if allnull:
			self.msg('all IP.IDs were 0...')
			sys.exit(0)
		ipids.sort()
		self.msg("we received the following IP.IDs: %s" % ipids)
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
					
			

	def send(self, dst, dport):
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
		self.msg("sending out %d SYN packets" % self.mpackets)
		a,u = scapy.sr(pkt * self.mpackets, timeout=2)
		self.msg("finished...")
		if a is not None:
			return a
		else:
			self.msg("uh... we did not recvd any response...")
			sys.exit(1)

