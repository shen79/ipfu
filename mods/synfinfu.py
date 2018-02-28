#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue, ipcalc, struct
from IPFU import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy
from netaddr import IPAddress

scapy.conf.verb = 0

class synfinfu(IPFU):
	"""synfinfu
	ipfu synfinfu <ip> <port>
	"""
	def __init__(self, params=None):
		try:
			self.ip = params[0]
			self.port = int(params[1])
		except:
			print self.__doc__
			if params is not None: exit(1)

	def start(self):
		self.synfinfu(self.ip, self.port)
	
	def synfinfu(self, ip, port):
		# modprobe nfnetlink_queue
		# apt-get install nfqueue-bindings-python python-netfilter
		#
		# current pid will be the queue_id 
		qid = os.getpid()
		log.msg("NFQueue ID: %d" % qid)

		# we gonna set up the queue
		nfq = nfqueue.queue()
		nfq.open()
		try:
			nfq.bind(socket.AF_INET)
		except RuntimeError as rte:
			log.err("umm... %s ... maybe nfqueue.unbind() wasn't successful last time... :/" % rte)
			log.err("try this: rmmod nfnetlink_queue; modprobe nfnetlink_queue")
			exit(1)
		nfq.set_callback(self.__synfin)
		nfq.create_queue(qid)
		log.msg("NFQueue up")
		# we need the rules
		# I tried to use python-netfilter but its undocumented
		# finally I figured out how to use but just cant use together with nfqueue
		os.system("iptables -A OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j NFQUEUE --queue-num %d" % (ip, port, qid))
		os.system("iptables -A OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j DROP" % (ip, port))
		log.msg("iptables rules up")
		log.msg("now you can try to connect to %s:%d with your favourite client" % (ip, port))
		# os.system("iptables -L OUTPUT")
		try:
			nfq.try_run()
		except KeyboardInterrupt:
			log.msg("kbd interrupt... ")
			os.system("iptables -D OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j NFQUEUE --queue-num %d" % (ip, port, qid))
			os.system("iptables -D OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j DROP" % (ip, port))
			log.msg("iptables rules down")
			nfq.unbind(socket.AF_INET)
			nfq.close()
			log.msg("NFQueue down")
			exit(1)

	def __synfin(self, i, payload):
		data = payload.get_data()
		p = scapy.IP(data)
		p[scapy.TCP].flags = "SF"
		del p[scapy.IP].chksum
		del p[scapy.TCP].chksum
		p = p.__class__(str(p))
		scapy.send(p);

