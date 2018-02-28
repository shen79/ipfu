#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


# flagfuzzer
class flagfuzzer(IPFU):
	"""flagfuzzer - TCP flag fuzzer
	ipfu flagfuzzer <tarrget_ip> <port> [full]
		by default it's playing around with FIN, SYN, ACK and RST flags (+2: SYN+URG, SYN+ECN)
	"""
	def __init__(self, params=None):
		try:
			self.dst = params[0]
			self.port = int(params[1])
			try:
				self.f = params[2]
				if self.f == 'full':
					self.scanflags = range(0,63)
			except:
				self.scanflags = ['','F','S','A','R','FS','FA','FR','SA','SR','AR','FSA','FSR','ARS', 'SU','SE']
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		self.flagfuzzer(self.dst, self.port)
	
	def flagfuzzer(self, dst, port):
		r = {
			'R':[],		# RST
			'RA':[],	# RST-ACK
			'SA':[],	# SYN-ACK
			'--':[],	# no response
			'??':[]		# ICMP error msgs (maybe... inspect this manually)
		}
		for flagval in self.scanflags:
			pkt = scapy.IP(dst=dst)
			pkt/= scapy.TCP(dport=port, sport=scapy.RandNum(1024,65535), flags=flagval)
			x = scapy.sr1( pkt, timeout=.5)
			sys.stderr.write(" %s   \r" % flagval)
			sent = pkt.sprintf("%TCP.flags%")
			if sent == '':
				sent = '-'
			if x is not None:
				recvd = x.sprintf("%TCP.flags%")
				#self.r[recvd].append(sent+"."+str(x[scapy.IP].ttl))
				r[recvd].append(sent)
			else:
				r['--'].append(sent)
		self.msg("finished")
		del r['--']
		self.msg("%4s: %s" % ('Recv', 'Sent'))
		for k in r.keys():
			self.msg("%4s: %s" % (k, " ".join(r[k])))



