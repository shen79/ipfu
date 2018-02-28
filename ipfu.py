#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
import importlib, scandir
sys.path.append("./mods")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0


if __name__ == "__main__":
	modulenames = []
	mf = scandir.walk("./mods")
	for i in list(mf)[0][2]:
		if i[-3:] == ".py":
			modulenames.append( i[:-3] )
	
	if len(sys.argv) < 2 or sys.argv[1] not in modulenames:
		print sys.argv[0],"<modulename>"
		print "modulenames:", ", ".join(modulenames)
		exit(1)
	mod = sys.argv[1]
	module = importlib.import_module(mod)
	class_ = getattr(module, mod)
	m = class_(sys.argv[2:])
	m.start()








