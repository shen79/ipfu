#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


class tsfu(IPFU):
	"""tsfu - TimeStamp-FU - exploiting the IP Options timestamp feature to leak intranet/network IPs and ranges
	ipfu tsfu <previous_ip> <target_ip> <port> <net>
	"""
	def __init__(self, params=None):
		try:
			self.prev_ip = params[0]
			self.target_ip = params[1]
			self.port = int(params[2])
			self.net = params[3]
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		self.tsfu(self.prev_ip, self.target_ip, self.port, self.net)

	# TODO: network/broadcast addr scan, bcoz this is slow... but effective
	def tsfu(self, prev_ip, target_ip, port, net):
		self.msg("checking for 127.0.0.1 ...")
		ptr_, oflw_, flag_ = self.__do_tsfu(prev_ip, target_ip, port, '127.0.0.1')
		if ptr_ is not False:
			self.msg("Okay, it works. (ptr=%-2d overflow=%d)" % (ptr_, oflw_))
		else:
			self.err("shit... :/")
			exit(0)
	
		self.msg("scanning ...")
		try:
			iplist = ipcalc.Network(net)
		except ValueError:
			iplist = self.__iplist(net)
		for test_ip in iplist:
#			print test_ip
			ptr, oflw, flag = self.__do_tsfu(prev_ip, target_ip, port, test_ip)
			if ptr is not None:
				dist_oflw = oflw_ - oflw
				if(dist_oflw == 0):
					info = "is known"
				else:
					info = "is known by another box behind this one."
				self.msg("%s %s (ptr=%-2d overflow=%d distance=%d)" % (test_ip, info, ptr, oflw, dist_oflw))

	def __do_tsfu(self, prev_ip, target_ip, port, test_ip):
		#        Opt_header________   IP1______________________    TS1_____    IP2______________________    TS2_____
		tsopts = '\x44\x14\x05\x03' + IPAddress(prev_ip).packed  + '\x00'*4  + IPAddress(test_ip).packed  + '\x00'*	4
		pkt = scapy.IP(dst=target_ip, proto=6, options=scapy.IPOption(tsopts))
		pkt/= scapy.TCP(sport=scapy.RandNum(1024,65535), dport=port)
		ret = scapy.sr1(pkt, timeout=1)
		if ret == None:
			return None, None, None
		#ret.show()
		optval = ret.options[0].value
		ts2bin = optval[14:]
		ts2 = struct.unpack('I', optval[14:])[0]
		ptr,x = struct.unpack('BB', optval[0:2])
		oflw = x >> 4
		flag = x & 0xF
		if(ts2):
			return ptr, oflw, flag
		return None, None, None

	def __iplist(self, expr):
		ret = []
		segs = expr.split('.')
#		print segs
		s = []
		for seg in segs:
			if seg == "*":
				seg = '0-255'
			se = seg.split(',')
			sa = []
			for s1 in se:
				s2 = s1.split('-')
				if len(s2) == 1:
					sa.append(int(s1))
				elif len(s2) == 2:
					for i in range(int(s2[0]), int(s2[1])+1):
						sa.append(i)
				else:
					self.err("invalid expression: '%s'" % expr)
					exit(1)
			s.append(sa)
#		print s
		# :///
		for a in s[0]:
			for b in s[1]:
				for c in s[2]:
					for d in s[3]:
						ret.append("%d.%d.%d.%d" % (a, b, c, d))
#		print ret
		return ret

