#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from IPFU import *
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


# gwscan module
class gwscan(IPFU):
	"""TODO gwscan
	ipfu gwscan <local_subnet> <target_ip/net>
	examples:
		ipfu gwscan 192.168.1.0/24 8.8.8.8
		ipfu gwscan 192.168.1.0/24 10.0.0.0/24
	"""
	def __init__(self, params=None):
		try:
			self.net = params[0]
			self.ip = params[1]
		except:
			print self.__doc__
			if params is not None: exit()

	def start(self):
		ret = self.gwscan_icmp(self.net, self.ip)
		for x in ret:
			print "%18s %16s %16s" % (x['gw_mac'], x['gw_ip'], x['r_ip'])

	def gwscan_icmp(self, net, ip):
		self.msg('gwscan for net %s, searching gw for %s' %(net, ip))
		lt = self.getmacs(net)
#		from pprint import pprint as pp
#		pp(lt)
		#ans,unans = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.IP(dst=ip) / scapy.ICMP(), timeout=5)
		pkt = scapy.Ether(dst=lt['mac_ip'].keys())
		pkt/= scapy.IP(dst=ip)
		pkt/= scapy.ICMP()
		ans,unans = scapy.srp( pkt, timeout=5)
		ret = []
		for b in ans:
			for a in b[1]:
				if a[scapy.ICMP].type == 0 and a[scapy.ICMP].code == 0:
					mac = a[scapy.Ether].src
					r_ip = a[scapy.IP].src
					if mac in lt['mac_ip']:
						ip = lt['mac_ip'][mac]
					else:
						ip = '_UNKNOWN'
						a.show()
					ret.append({
						'ttype':	'ping',
						'gw_mac':	mac,
						'gw_ip':	ip,
						'r_ip':		r_ip
					})
						
		self.msg('gwscan finished')
		return ret
