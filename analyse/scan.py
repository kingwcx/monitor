# -*- coding: UTF-8 -*-

from scapy.all import *

def pack_callback(packet):
	try:
		print("IP:SRC:%s -> DST:%s" % (packet[IP].src, packet[IP].dst))
	except:
		packet.show()
	#packet.show()

def capture():
	print('capturing....')
	dpkt = sniff(prn=pack_callback, filter="ip")
	#dpkt = sniff(10)
	wrpcap("../datas/pkts.pcap", dpkt)
	return dpkt

if __name__ == '__main__':
	capture()
	print('.....')
else:
	pass