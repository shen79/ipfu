#!/usr/bin/python
""" IPFU helper function """

import logging
import inspect
import netaddr, netifaces
from scapy import all as scapy

# prevent scapy warnings for ipv6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy.conf.verb = 0

class IPFU(object):
    """ Our helper logger class """
    def __init__(self):
        pass
    def __pfu_out(self, msg, msgcolor):
        """ used for printing """
        color = {\
        "mod": '\033[90m',\
        "msg": '\033[94m',\
        "err": '\033[91m',\
        "end": '\033[0m'}
        mod = []
        for frame in reversed(inspect.stack()[2:-2]):
            mod.append(frame[3])
        print color["mod"] + '.'.join(mod) +' > ' +\
        color[msgcolor] + str(msg) + color["end"]

    def msg(self, msg):
        """ wrapper for __pfu_out """
        self.__pfu_out(msg, "msg")
    def err(self, msg):
        """ wrapper for __pfu_out """
        self.__pfu_out(msg, "err")

    def getMyIP(self, iface):
        """ return IP of iface parameter interface """
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

    def getMyNet(self, iface):
        """ return net? """
        ip_address = self.getMyIP(iface)
        bits = str(netaddr.IPAddress(\
                netifaces.ifaddresses(iface)\
                [netifaces.AF_INET][0]['netmask']).netmask_bits())
        net = netaddr.IPNetwork(ip_address+'/'+bits)
        ret = str(net.network) + '/' + bits
        return ret

    def getmacs(self, target):
        """ get scapy arping for target and order it """
        address_table = {'ip_mac': {}, 'mac_ip': {}}
        self.msg('arping in progress')
        answers, unans = scapy.arping(target)
        self.msg('arping finished')
        for answer in answers:
            # a[1].show()
            # get mac and ip from scapy output
            mac_addr = answer[1][scapy.ARP].hwsrc
            ip_addr = answer[1][scapy.ARP].psrc
            # one MAC can have multiple IP addresses, so mac_ip
            # will have mac - ip_array pairs
            if mac_addr in address_table['mac_ip']:
                address_table['mac_ip'][mac_addr].append(ip_addr)
            else:
                address_table['mac_ip'][mac_addr] = [ip_addr]
            # one ip can be paired to only one MAC address
            address_table['ip_mac'][ip_addr] = mac_addr
        # {'ip_mac': {'192.168.110.1': 'e4:8d:8c:a0:e8:a9'},
        #  'mac_ip': {'e4:8d:8c:a0:e8:a9': ['192.168.110.1']}}
        return address_table
