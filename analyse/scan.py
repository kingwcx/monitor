# -*- coding: UTF-8 -*-

from scapy.all import *

def pack_callback(packet):
	try:
		print("IP:SRC:%s -> DST:%s" % (packet[IP].src, packet[IP].dst))
	except:
		packet.show()
	#packet.show()

def capture():
	print('debug:testing')


if __name__ == '__main__':
	capture()
	print('.....')
else:
	pass