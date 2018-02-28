#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
sys.path.append("./libs")
from mixins import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


# flagfuzzer
class flagfuzzer(loggerMixin):
	def __init__(self, params):
		if len(params) != 2:
			self.usage()
			exit(1)
		self.dst = params[0]
		self.port = int(params[1])

	def usage(self):
		print "Usage:"
		print "\t%s tcp.flagfuzzer <target_ip> <port>" % sys.argv[0]

	def start(self):
		self.flagfuzzer(self.dst, self.port)
	
	def flagfuzzer(self, dst, port):
		r = {
			'R':[],		# RST
			'RA':[],	# RST-ACK
			'SA':[],	# SYN-ACK
			'--':[],	# no response
			'??':[]		# ICMP error msgs (?)
		}
		scanflags = ['','F','S','FS','R','RF','RS','RSF','A','AF','AS','ASF','AR','ARF','ARS','ARSF']
#		scanflags = range(0,21)
		for flagval in scanflags:
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
		for k in r.keys():
			self.msg("%4s: %s" % (k, " ".join(r[k])))



