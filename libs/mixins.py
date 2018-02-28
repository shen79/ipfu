#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
import importlib, scandir
sys.path.append("./mods")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0

# Our helper logger class
class loggerMixin:
	def __pfu_out(self, msg, msgcolor):
		color = {  "mod": '\033[90m', "msg": '\033[94m',
				"err": '\033[91m', "end": '\033[0m' }
		mod = []
		for fr in reversed(inspect.stack()[2:-2]):
			mod.append(fr[3])
		print color["mod"] + '.'.join(mod) +' > '+ color[msgcolor] + str(msg) + color["end"]

	def msg(self, msg):
		self.__pfu_out(msg, "msg")
	def err(self, msg):
		self.__pfu_out(msg, "err")

# global logger instance
#log = logger()

# getmacs mixin
class GetMacsMixin(loggerMixin):
	def getmacs(self, target):
		ret = {'ip_mac': {}, 'mac_ip': {}}
		self.msg('arping in progress')
		ans,unans = scapy.arping(target)
		self.msg('finished')
		for a in ans:
#			a[1].show()
			mac = a[1][scapy.ARP].hwsrc
			ip = a[1][scapy.ARP].psrc
			if mac in ret['mac_ip']:
				ret['mac_ip'][mac].append(ip)
			else:
				ret['mac_ip'][mac] = [ip]
			ret['ip_mac'][ip] = mac
		return ret



