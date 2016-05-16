#!/usr/bin/env python

###############################################################################################################
## [Title]: recon.py -- a recon/enumeration script
## [Original Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift --Thanks Man!
## [Author]: Brandon Dennis (Slyth)
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such 
## as HTTP/
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I strictly wrote it for personal use
## I have no plans to maintain updates, I did not write it to be efficient and in some cases you may find the 
## functions may not produce the desired results so use at your own risk/discretion. I wrote this script to 
## target machines in a lab environment so please only use it against systems for which you have permission!!  
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os, sys, re
import time 

def multProc(targetin, scanip, port, buildPath):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port,buildPath))
    jobs.append(p)
    p.start()
    return

def usage():
	print("\n[-] Usage: %s /root/IP-List.txt" % sys.argv[0])
	print("[-] Can be a single ip ex: %s 127.0.0.1 or a file(/root/IP-List.txt)\n" % sys.argv[0])

def is_valid_ipv4_address(address):
	m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", address)
	return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

#
#
# This starts our user def functions for each protocols enumeration
#
#

def HTTPEnum(ip_address, port, buildPath):
	#Running Nikto
	print("[*] INFO: Running Nikto on %s:%s") % (ip_address,port)
	NIKTO="nikto -C all -h %s:%s > %s%s-%s.nikto" % (ip_address,port,buildPath,ip_address,port)
	NiktoResults = subprocess.check_output(NIKTO, shell=True)
	print("[*] INFO: Running Nmap HTTP Scan on %s:%s") % (ip_address,port)
	NmapHTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN %s%s_http-%s.nmap %s" % (port, buildPath,ip_address, port, ip_address)
	subprocess.check_output(NmapHTTPSCAN, shell=True)
	print("[*] INFO: Running dirbust on %s:%s") % (ip_address,port)
	DIRBUST = "./dirbust.py http://%s:%s %s %s" % (ip_address, port, ip_address, buildPath) # execute the python script
	subprocess.call(DIRBUST, shell=True) # Runs the script, the script will provide the output to a file
	return

#
#
# This ends our user def functions for each protocols enumeration
#
#



def nmapScan(ip_address, jobs):

	BasePathResults = "/root/recon/results/" #CHANGE THIS---------------------------------------------CHANGE THIS

	#Strips out the \n
	ip_address = ip_address.strip()

	#Once the IP has been verified we need to check if the path in BasePathResults is there if not create it
	if os.path.exists(BasePathResults) == False:
		#This will also append the IP as a dir to the path
		#Create the path
		tmpPath = BasePathResults.split("/")
		tmpPath = [i for i in tmpPath if i != ''] # this removes the empty strings at the first and last element
		buildpath = ""
		for direct in tmpPath:
			buildpath += "/" + direct
			if os.path.exists(buildpath) == False:
				os.makedirs(buildpath)	

	#This means the path is there so we can create the dir and set the new BasePathResults
	BasePathResults = BasePathResults+ip_address.replace(".","-")+"/"
	if os.path.exists(BasePathResults) == False: 
		os.makedirs(BasePathResults)
		

	print "\n[*] INFO: Running general TCP/UDP nmap scans for " + ip_address
	TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '%s%s.nmap' -oX '%s%s_nmap_scan_import.xml' %s"  % (BasePathResults, ip_address, BasePathResults, ip_address, ip_address)
	UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s%sU.nmap' -oX '%s%sU_nmap_scan_import.xml' %s" % (BasePathResults, ip_address, BasePathResults, ip_address, ip_address)
	
	#Runs the nmap scans
	tcpresults = subprocess.check_output(TCPSCAN, shell=True)
	udpresults = subprocess.check_output(UDPSCAN, shell=True)

	#Parses the results
	lines = tcpresults.split("\n")
	lines = [i for i in lines if i != ''] # Removes empty strings
	enumDir = {}
	unknownService = {}

	for line in lines:
		line = line.strip() #Strip newlines,etc
		if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
			while "  " in line:
				line = line.replace("  "," ")
				line = line.replace("/tcp open "," ")
			
			line = line.split(" ")
			enumDir[line[0]] = line[1]

	#This will run the seperate function for each service found, use multiproc to run each new function
	for port, serv in enumDir.items():
		if ("http" in serv) or ("https" in serv):
			print("[*] INFO: Enumerating %s on port %s..") % (serv,port)
			multProc(HTTPEnum, ip_address, port, BasePathResults)
		elif ("ssh" in serv):
			print(" INFO:Service is SSH: %s" % port)
		elif ("smtp" in serv):
			print(" INFO:Service is SMTP: %s" % port)
		else:
			unknownService[serv] = port

	if bool(unknownService):
		print("\n[*] Unknown Service's\n[*] Please Review, Reasearch & Add to the application\n")
		print("[*]\t  Service's\t|      Port")
		print("#" * 40)
		for serv, port in unknownService.items():
			print("# %18s\t|     %5s    #") % (serv, port)
		print ("#" * 40)

	print "\n[*] INFO: TCP/UDP Nmap scans completed for %s" % ip_address
	print "\n[*] INFO: Be sure to check the UDP scans Logs for %s" % ip_address 
	return


# grab the discover scan results and start scanning up hosts
os.system("clear")
print "############################################################"
print "####                        RECON                       ####"
print "####            A multi-process service scanner         ####"
print "############################################################"
 
if __name__=='__main__':
   
	if (len(sys.argv) < 2 or len(sys.argv) > 2):
		usage()
		sys.exit(0)
	
	#Check if its an IP (If not an ip its a path)
	checkIP = is_valid_ipv4_address(sys.argv[1])
	jobs = []

	if checkIP == True:
		p = multiprocessing.Process(target=nmapScan, args=(sys.argv[1],jobs,))
		jobs.append(p)
		p.start()
	else:
		if os.path.exists(sys.argv[1]) == True: # Checks if the path is valid
			f = open(sys.argv[1], 'r') 
			for scanip in f:
				p = multiprocessing.Process(target=nmapScan, args=(scanip,jobs,))
				jobs.append(p)
				p.start()
			f.close()
		else:
			print("File %s not Found" % sys.argv[1])
	sys.exit(0)
