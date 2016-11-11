#!/usr/bin/python
import sys
import os
import time
from collections import defaultdict
import numpy

#Author: Brandon Dennis
#Date: 11/8/16
#Company: Radiant Logic Inc.


#Globals
#ERROR CODES
errorCodes = {}
errorCodes[0]="successful"
errorCodes[1]="operations error"
errorCodes[2]="protocol error"
errorCodes[3]="timelimit exceed"
errorCodes[4]="sizelimit exceeded"
errorCodes[5]="compare false"
errorCodes[6]="compare true"
errorCodes[7]="strong auth not supported"
errorCodes[8]="strong auth required"
errorCodes[9]="partial results"
errorCodes[10]="referral"
errorCodes[11]="admin limit exceeded"
errorCodes[16]="no such attribute"
errorCodes[17]="undefined type"
errorCodes[18]="inappropriate matching"
errorCodes[19]="constraint violation"
errorCodes[20]="type or value exists"
errorCodes[21]="invalid syntax"
errorCodes[32]="no such object"
errorCodes[33]="alias problem"
errorCodes[34]="invalid DN syntax"
errorCodes[35]="is leaf"
errorCodes[36]="alias deref problem"
errorCodes[48]="inappropriate auth"
errorCodes[49]="invalid credentials"
errorCodes[50]="insufficient access"
errorCodes[51]="busy"
errorCodes[52]="unavailable"
errorCodes[53]="unwilling to perform"
errorCodes[54]="loop detect"
errorCodes[64]="naming violation"
errorCodes[65]="object class violation"
errorCodes[66]="not allowed on nonleaf"
errorCodes[67]="not allowed on RDN"
errorCodes[68]="already exists"
errorCodes[69]="no object class mods"
errorCodes[70]="results too large"
errorCodes[80]="other"
errorCodes[81]="server down"
errorCodes[82]="local error"
errorCodes[83]="encoding error"
errorCodes[84]="decoding error"
errorCodes[85]="timeout"
errorCodes[86]="auth unknown"
errorCodes[87]="filter error"
errorCodes[88]="user cancelled"
errorCodes[89]="param error"
errorCodes[90]="no memory"
errorCodes[91]="connect error"


def helpMenu():

	print("\n----------\tVDS Log Analyzer Help Menu\t----------")
	print("\n\tOptions:\t\t<Log File>\t Note: If you provide a full path use a set of \". EX: \"C:\\vds_server.log\"")
	print("\n\n  Usage: python " + sys.argv[0] + " [options]")
	print("\n  Example: python " + sys.argv[0] + " vds_server.log")


#Checks to see if a logs file has been attached.
if (len(sys.argv) <= 1):
	helpMenu()
	exit(1)
	
	
def checkFile(filePath):
	#Check if the file exists & can be read
	if(os.path.isfile(filePath) == False):
		print("\n[ERROR]: File not Found or Cannot be Read.")
		exit(1)


def gatherContents(file_handle):
	#Here we create a temp array to hold the values and we pass this array back to main with all of the data added.
	tmpContents = []
	for line in file_handle.readlines():
		tmpContents.append(line)
	
	return tmpContents
	
def guessLogLevel(contents):
	#Here we will attempt to guess the log level of these logs
	currHighestLevel = 0
	currHighestLevelStatus = "OFF"
	for line in contents:
		if "WARN" in line:
			if(1 >= currHighestLevel):
				currHighestLevel = 1
				currHighestLevelStatus = "WARN"
		if "INFO" in line:
			if(2 >= currHighestLevel):
				currHighestLevel = 2
				currHighestLevelStatus = "INFO"
		if "DEBUG" in line:
			if(3 >= currHighestLevel):
				currHighestLevel = 3
				currHighestLevelStatus = "DEBUG"
		if "TRACE" in line:
			if(4 >= currHighestLevel):
				currHighestLevel = 4
				currHighestLevelStatus = "TRACE"
		if(currHighestLevel == 0):
			currHighestLevelStatus = "OFF/FATAL/ERROR"
	
	return currHighestLevelStatus
	
	
def checkVDSLastStart(contents):
	#Here we will gather the latest start/stop times if they are found
	startString = "VDS is starting"
	stopString = "VDS_Server is shutting-down"
	startTime = "VDS Was Not Started In This Log."
	stopTime = "VDS Was Not Stopped In This Log."
	for line in contents:
		if startString in line:
			startTime = line.split(",")[0]
		if stopString in line:
			stopTime = line.split(",")[0]

	return startTime, stopTime
	
def checkGlobalIntercept(contents):
	#We are checking to see if there is a possible global interception script running
	isGlobal = False
	isLocal = True
	for line in contents:
		if "globalIntercept" in line:
			isGlobal = True
		if "Before Interception" in line:
			isLocal = True
			
			
			
	return isGlobal, isLocal
	
def getClients(contents):
	#Here we gather all of the uniq client IP's
	client = "CLIENT("
	server = "SERVER("
	connect = "connected on"
	serverIP = "127.0.0.1"
	clients = []
	
	#First we need to get the IP of the server so we can ignore this during the client gathering
	for line in contents:
		if server in line:
			if connect in line:
				serverIP = line.split(" ")[11].split("(")[1].split(":")[0]
		
	#now we are going to parse through and grba the client ip's
	for line in contents:
		if client in line:
			if connect in line:
				tmp = line.split(" ")[8].split("(")[1].split(":")[0]
				if tmp not in serverIP:
					clients.append(tmp)
					
	#This will remove all duplicates from the array and make it a list
	clients = list(set(clients))

			
	return clients
	
def gatherConnections(contents):
	#Here we are placing all of the connections and intl connections and their respective data in an array for use later
	#We do this so we have the raw data and can create functions later to parse specific things refering to the data
	connIds = []
	intlIds = []
	
	for line in contents:
		if "conn=" in line:
			connIds.append(line.split(" ")[7].split("=")[1])
		if "intl=" in line:
			intlIds.append(line.split(" ")[7].split("=")[1])
		
	connIds = list(set(connIds))
	intlIds = list(set(intlIds))
	connectionsConn = {}
	connectionsIntl = {}

	i = 0
	for line in contents:
		if "conn=" in line:
			currentConnNumber = line.split(" ")[7].split("=")[1]
			for id in connIds:
				if(currentConnNumber == id):
					connectionsConn.setdefault(id, []).append(line)
					i += 1
					break
					
		if "intl=" in line:
			currentIntlNumber = line.split(" ")[7].split("=")[1]
			for id in intlIds:
				if(currentIntlNumber == id):
					connectionsIntl.setdefault(id, []).append(line)
					i += 1
					break
	
	return connectionsConn, connectionsIntl, connIds, intlIds
	
def getTopEtimes(rawConnData, rawIntlData, connIds):
	#This will grab the 5 largest etimes that can be found in the log
	top5Etimes = [0,0,0,0,0,0]
	#				Time,ID,TYPE
	top5Etimes[0] = [0, 0, "TMP"]
	top5Etimes[1] = [0, 2, "SearchResult"]
	top5Etimes[2] = [0, 5, "BindResponse"]
	top5Etimes[3] = [0, 1, "SearchResult"]
	top5Etimes[4] = [0, 7, "ModifyResponse"]
	top5Etimes[5] = [0, 7, "BindResponse"]

	
	i = 0
	for conn in rawConnData:
		tmparray = rawConnData[connIds[i]]
		for data in tmparray:
			if "etime=" in data:
				tmpTime = int(data.split("etime=")[1].split(" ")[0].replace(" ", ""))
				tmpType = data.split(" ")[10].replace(" ", "")
				top5Etimes[0] = [int(tmpTime), int(connIds[i]), str(tmpType)]
				top5Etimes.sort()

		i += 1
		
				
	return top5Etimes
	
def printTopETimes(top5Etimes):
	ignoreFirst = 0
	print("\tConnection ID\tETime\tRequest Type")
	print("\t------------------------------------")
	for num in top5Etimes:
		if(ignoreFirst != 0):
			print("\t" + str(num[1]), end="")
			print("\t\t" + str(num[0]), end="")
			print("\t" + num[2], end="")
			print("\n", end="")
		ignoreFirst += 1
	return
	
	
def getCurrentErrors(rawConnData, rawIntlData, connIds, intlIds):
	
	#This will get the errors and the total count to print out the % of each
	resultCodes = []
	totalResults = 0
	
	i = 0
	for conn in rawConnData:
		tmparray = rawConnData[connIds[i]]
		for data in tmparray:
			if "resultCode" in data:
				resultCodes.append([int(data.split(" ")[11].split("=")[1].split(",")[0]), data.split(" ")[10].replace(" ", ""), int(data.split(" ")[7].split("=")[1])])
				totalResults += 1

		i += 1
		
	i = 0
	for intl in rawIntlData:
		tmparray = rawIntlData[intlIds[i]]
		for data in tmparray:
			if "resultCode" in data:
				resultCodes.append([int(data.split(" ")[11].split("=")[1].split(",")[0]), data.split(" ")[10].replace(" ", ""), int(data.split(" ")[7].split("=")[1])])
				totalResults += 1

		i += 1
	
	
	totalResultCodes = []
	resultCodes.sort()
	for code in resultCodes:
		currCode = code[0]
		currType = code[1]
		currID = code[2]
		if any(currCode in lcode for lcode in totalResultCodes):
			for newCount in range(len(totalResultCodes)):
				if (str(currCode) == str(totalResultCodes[newCount][0])):		
					totalResultCodes[newCount] = [currCode, (totalResultCodes[newCount][1] + 1)]
		else:
			totalResultCodes.append([currCode, 1])
		
	

	return totalResultCodes, totalResults
	
def printErrors(currentErrors, totalResults):
	
	print("\tResult Code\tCount\tPercentage\tError Reason")
	print("\t----------------------------------------------------------")
	for error in currentErrors:
		print("\t" + str(error[0]) + "\t\t" + str(error[1]) + "\t" + str(round(((error[1] / totalResults) * 100), 2)) + "%\t\t" + errorCodes[error[0]])
	return
	
def main():

	#Var's
	filePath = sys.argv[1] #Setting the path
	contents = [] #This will be an array of each line in the log

	print("\n----------\tVDS 7.2 Log Analyzer\t----------")
	
	print("\n\n[*] Checking File.... ", end="")
	#Checks if the file can be accessed and read
	checkFile(filePath)
	file_handle = open(filePath, 'r') #Open the file stream to access the contents in read only mode
	print("Done")
	
	print("\n[*] Parsing File.... ", end="")
	#We now set the contents line by line in the log file to an array
	#We will also parse all of the connections conn and intl and their data
	contents = gatherContents(file_handle)
	rawConnData, rawIntlData, connIds, intlIds = gatherConnections(contents)
	print("Done")
	
	print("\n[*] Guessing Current Log Level.... ", end="")
	#We now take a guess at what the current log level is set to
	logLevel = guessLogLevel(contents)
	print("Done")
	print("\t[*] Log Level: " + logLevel)
	
	print("\n[*] Checking Last VDS Start & Stop Time.... ", end="")
	#We now look for the last instance of VDS starting
	vdsStartTime, vdsStopTime = checkVDSLastStart(contents)
	print("Done")
	print("\t[*] Last VDS Start Time: " + vdsStartTime)
	print("\t[*] Last VDS Stop Time: " + vdsStopTime)
	
	print("\n[*] Checking for Global & Local Interception Scripts.... ", end="")
	#We are now checking if we see a global interception script running
	isGlobal, isLocal = checkGlobalIntercept(contents)
	print("Done")
	globaltmp = 'Found' if isGlobal else 'Not Found'
	localtmp = 'Found' if isLocal else 'Not Found'
	print("\t[*] Global Interception:   " + globaltmp)
	print("\t[*] Local Interception:    " + localtmp)
	
	print("\n[*] Gathering List Of Clients.... ", end="")
	#We now look for the last instance of VDS starting
	clients = getClients(contents)
	print("Done")
	for client in clients:
		print("\t[*] Client: " + client)
		
	print("\n[*] Gathering List Of Largest etime's.... ", end="")
	#We now look for the top 5 largest etime results
	topEtimes = getTopEtimes(rawConnData, rawIntlData, connIds)
	print("Done")
	printTopETimes(topEtimes)
	
	print("\n[*] Checking For Errors.... ", end="")	
	#This will look for all of the errors found and return the error(what it means)
	currentErrors, totalResults = getCurrentErrors(rawConnData, rawIntlData, connIds, intlIds)
	print("Done")
	printErrors(currentErrors, totalResults)

	
	print("\n\n[*] VDS 7.2 Log Analyzer Complete!")
	exit(0)
	
main()
