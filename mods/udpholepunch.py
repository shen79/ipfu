#!/usr/bin/python

import logging, sys
from IPFU import *
from scapy import all as scapy
#from netaddr import IPAddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
scapy.conf.verb = 0

# udpholepunch
class udpholepunch(IPFU):
	"""TODO udpholepunch - holepunching for UDP
	ipfu udpholepunch <interface> <router_mac> <serverip> <dns> <attacker-ip> <dns-domain>
	TODO ipfu udpholepunch <interface> <router_mac> <serverip> <snmp> <attacker-ip> <snmp-community> <snmp-version>
	TODO ipfu udpholepunch <interface> <router_mac> <serverip> <ntp> <attacker-ip>
	Examples:
		TODO
	"""
	def __init__(self, params=None):
		try:
			# buggz
			self.interface = params[0]
			self.router_mac = params[1]

			self.server_ip = params[2]
			self.proto = params[3]
			self.attacker_ip = params[4]
		except:
			print self.__doc__
			if params is not None: sys.exit(1)
		try:
			if self.proto == 'dns':
				self.domain = params[5]
			elif self.proto == 'snmp':
				self.community = params[5]
				self.version = params[6]
			elif self.proto == 'ntp':
				pass
		except:
			print self.__doc__
			sys.exit(2)

			

	def start(self):
		if self.proto == 'dns':		self.dnspunch()
		elif self.proto == 'snmp':	self.snmppunch()
		elif self.proto == 'ntp':	self.ntppunch()
	
	def dnspunch(self):
		# punchpkt
		e = scapy.Ether(dst=self.router_mac)
		self.msg("sending punchies...")
		pkt = scapy.IP(src=self.server_ip, dst=self.attacker_ip)
		pkt/= scapy.UDP(sport=53, dport=53)
		pkt/= scapy.Raw("udp holepunch test")
		scapy.sendp(e / pkt, iface=self.interface)

		# rqpkt
		self.msg("sending DNS request to %s asking %s..." % (self.server_ip, self.domain))
		pkt = scapy.IP(src=self.attacker_ip, dst=self.server_ip)
		pkt/= scapy.UDP(sport=53, dport=53)
		pkt/= scapy.DNS(rd=1, qd=scapy.DNSQR(qname=self.domain))

		x,u = scapy.srp(e/ pkt, timeout=5, iface=self.interface)
		self.msg('ok')

		for p in x[0]:
			p.show()
			if p[1].proto == 1:
				print "%s %s/%s" %( p[1].sprintf("%IP.src%"), p[1].sprintf("%ICMP.type%"), p[1].sprintf("%ICMP.code%") )
			else:
				p[1].show()





