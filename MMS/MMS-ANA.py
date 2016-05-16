#!/usr/bin/python

#Author: Brandon Dennis
#Date: 8/16/15
#Interop Technologies
#MMS Traffic Monitor/Capture Script

import socket, sys
from struct import *
import binascii
import getopt

#VARS
MAX_PACKET_SIZE = 65565
ProtType = ""
ETH_Header_Length = 14
IP_Header_Length = ETH_Header_Length + 20
TCP_Header_Length = IP_Header_Length + 16
hasArgs = False
AppName = sys.argv[0]

def Help():
	
	help_text = """
===================================================================
Usage: %(AppName)s --p tcp

OPTION:
	--h	This Screen	

	--p	(tcp, udp, all) Default: tcp

===================================================================

		    """ % {'AppName': AppName}

	print(help_text)

	try:
		sys.exit()
       	except SystemExit:
		pass

def CheckArgs():
	
	if len(sys.argv) >= 4:
		Help()	
	
	options = {}

	try:
		options, remainder = getopt.getopt(sys.argv[1:], 'ph', ['protocol=','help'])
	except getopt.GetoptError, e:
		print(e)
	
	for opt, arg in options:
		if opt in ('--p', '--protocol'):
			if arg.lower() == 'tcp' or arg.lower() == 'udp' or arg.lower() == 'all':
				filter = arg
			elif arg.lower() == '--h' or arg.lower() == '-h' or arg.lower() == '--help':
				Help()
			else:
				filter = 'tcp' #This is our default if anything else is picked
			hasArgs = True
		else:
			filter = ''
			hasArgs = False
			Help()
	

def Hex2Ascii(hex):
	return binascii.unhexlify(hex)


def Hex2Decimal(hex):
	
	try:
		New_String = str(int(hex, 16))
	except ValueError:
		return 0
	
	return New_String

def eth_addr(eth):
	#This converts a string  to 6 chars eth addr into a dash separated MAC
	converted = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (ord(eth[0]) , ord(eth[1]) , ord(eth[2]), ord(eth[3]), ord(eth[4]) , ord(eth[5]))
	return converted

def ParseEthernetHeader(packet):

	src_dst_mac = []
	src_dst_mac.append(str(eth_addr(packet[0:6])))
	src_dst_mac.append(str(eth_addr(packet[6:12])))
	
	return src_dst_mac
	 

def ParseTCPHeader(hex_TCP):

	#Below is the order of the slices, this is the same order as the array returned
	#Source Machine Port
	#Destination Port
	#ACK Num
	#TCP Header Length
	#Window Size

	TCP_Header_POS = [(0,4),(4,8),(8,16),(16,17),(18,22)]
	TCP_Data_Parts = ""
	for info in TCP_Header_POS:

		TCP_Data_Parts += hex_TCP[info[0]:info[1]] + " "

	TCP_Data_PartsList = TCP_Data_Parts.split(" ")
	#This removes the last entry since it is always a space " "
        TCP_Data_PartsList.pop()

	#This will convert all required parts to decimal/ASCII
	for x in range(0, len(TCP_Data_PartsList)):
		TCP_Data_PartsList[x] = Hex2Decimal(TCP_Data_PartsList[x])	

	return TCP_Data_PartsList


def ParseIPHeader(hex_IP):
	
	#Below is the order of the slices, this is the same order as the array returned
	#Version
	#Header Length
	#Total Length
	#TTL
	#Protocol
	IP_Header_Pos = [(0,1),(1,2),(3,7),(16,18),(18,20)]
	IP_Data_Parts = ""
	for info in IP_Header_Pos:

		IP_Data_Parts += hex_IP[info[0]:info[1]] + " "
	
	IP_Data_PartsList = IP_Data_Parts.split(" ")
	#This removes the last entry since it is always a space " "
	IP_Data_PartsList.pop()

	return IP_Data_PartsList

def Start_Capture():
	
	#Attempt to create the socket
	try:
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	except socket.error, msg:
		print('Could not create socket, Error Code:' + msg[0] + ' Message: ' + msg[1])

	while True:
		try:
			#Gets the packet data in HEX from the socket
			packet = sock.recvfrom(MAX_PACKET_SIZE)		
			
			#packet string from tuple
			packet = packet[0]	

			#We need to grab the Ethernet Frames
			hex_ETH = ParseEthernetHeader(packet)

			#Now we grab the IP header, this is the first 20 chars
			IP_Header = packet[ETH_Header_Length:IP_Header_Length]
			
			#This will unpack it to allow us to pull the src and dest addr
			IP_Header_INET_Addr = unpack('!BBHHHBBH4s4s', IP_Header)
		
			#This will convert the weird string to HEX to parse through
			hex_IP = binascii.hexlify(IP_Header)
			IP_Data = ParseIPHeader(hex_IP)

			#Parse through to get the src and dest addr
			src_addr = socket.inet_ntoa(IP_Header_INET_Addr[8])
            dst_addr = socket.inet_ntoa(IP_Header_INET_Addr[9])

			
			if int(Hex2Decimal(IP_Data[4])) == 6:
				ProtType = "TCP"
			elif int(Hex2Decimal(IP_Data[4])) == 1:
				ProtType = "ICMP"
			elif int(Hex2Decimal(IP_Data[4])) == 2:
				ProtType = "IGMP" 
			elif int(Hex2Decimal(IP_Data[4])) == 17:
        	                ProtType = "UDP"
			elif int(Hex2Decimal(IP_Data[4])) == 11:
				ProtType = "NVP"
			else:
				ProtType = "UNKNOWN"
			

			#Pulls the TCP header from the packet
			TCP_Header = packet[IP_Header_Length:TCP_Header_Length]
			
			#Moves the binary to hex
			hex_TCP = binascii.hexlify(TCP_Header)
			
			#This parses and retrieves the data we need
			TCP_Data = ParseTCPHeader(hex_TCP)
			
			#this will provide the data part of the packet
			data = packet[TCP_Header_Length:]

			#We are going to print the Ethernet frames
                        print('\n\nDestination MAC: ' + hex_ETH[0] + ' Source MAC: ' + hex_ETH[1])

                        #We are going to print the IP header
                        print('Version: ' + str(IP_Data[0]) + ' IP Header Length: ' + str(IP_Data[1]) + ' Total TCP Packet Length: ' + str(IP_Data[2]) + ' TTL: ' + str(Hex2Decimal(IP_Data[3])) + ' Protocol: ' + str(IP_Data[4] + "(" + ProtType + ")") + ' Source: ' + str(src_addr) + ' Destination: ' + str(dst_addr))

			#We are going to print our TCP header
                        print('Source Port: ' + str(TCP_Data[0]) + ' Destination Port: ' + str(TCP_Data[1]) + ' ACK #: ' + str(TCP_Data[2]) + ' TCP Header Length: ' + str(TCP_Data[3]) + ' Window Size: ' + str(TCP_Data[4]))

			#We now print our data
			#print(data)





		except KeyboardInterrupt:
			break


def main():
	CheckArgs()
	if hasArgs:
	#	Start_Capture()
		print ('Start_Capture')
		print('Filter:' + str(filter))
	print('GoodBye')



if __name__ == '__main__':
	main()

