# -*- coding: UTF-8 -*-
from scapy.all import *

def save(dpkt,object):
	print('debug：save'+object)
	path = "datas/"+object+"/pkts.pcap"
	wrpcap(path, dpkt)