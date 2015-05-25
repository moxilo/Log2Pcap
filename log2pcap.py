#!/usr/bin/python
# -*- encoding: utf-8 -*-

import argparse
import time
import sys

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

"""
V0.1: Dic 2012, SANS GCIA GOLD.
V0.2: April 2015, Enzo Version, dedicated to @Spankito.
 - Functions to class.
 - Timestamp parsing.
 - Storage every X connections instead of every network packet.
 - IPv6 in Apache error resolved.
 - Argparse implemented.
 - Tomcat Support added.
 - Process evolution.
 TODO:
 - Resume the process.
"""

__author__ = "Joaquin Moreno Garijo @moxilo"
__version__ = "0.2"
__email__ = "bastionado@gmail.com"
__status__ = "Developping" 


class ipv4Tcp():
	def __init__(self, serverIp, serverPort):
		self.dstIp = serverIp
		self.dstPort = serverPort
		self.srcPort = "30003"
		
	def handshake(self, srcIp, tm):
		pkts = []
		# Move this to constructor to be faster. (Some app will complain)
		self.srcPort = int(random.getrandbits(16))
		while self.srcPort < 1024:
			self.srcPort = int(random.getrandbits(16))
		#Random seq
		seqN = random.getrandbits(32)
		ackN = 0
		#Syn
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="S",seq=seqN,ack=ackN)
		pkt.time = tm
		pkts.append(pkt)
		#Random ack
		ackN = random.getrandbits(32)
		#Syn+ack, ack
		pkt = IP(dst=srcIp,src=self.dstIp)/TCP(dport=int(self.srcPort),sport=int(self.dstPort),flags="SA",seq=ackN,ack=seqN+1)
		pkt.time = tm
		pkts.append(pkt)
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="A",seq=seqN+1,ack=ackN+1)
		pkt.time = tm
		pkts.append(pkt)
		return (pkts, seqN+1, ackN+1)

	def resetconnection(self, srcIp, seqN, ackN, tm):
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="R",seq=seqN,ack=ackN)
		pkt.time = tm
		return [pkt]

	def finishconnection(self, srcIp, seqN, ackN, tm):
		pkts = []
		#Client FA 
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="FA",seq=seqN,ack=ackN)
		pkt.time = tm
		pkts.append(pkt)
		seqN = seqN + 1
		pkt = IP(dst=srcIp,src=self.dstIp)/TCP(dport=int(self.srcPort),sport=int(self.dstPort),flags="A",seq=ackN,ack=seqN)
		pkt.time = tm
		pkts.append(pkt)
		#Server FA
		pkt = IP(dst=srcIp,src=self.dstIp)/TCP(dport=int(self.srcPort),sport=int(self.dstPort),flags="FA",seq=ackN,ack=seqN)
		pkt.time = tm
		pkts.append(pkt)
		ackN = ackN + 1
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="A",seq=seqN,ack=ackN)
		pkt.time = tm
		pkts.append(pkt)
		return pkts

	def queryResponse(self, srcIp, seqN, ackN, query, response, tm):
		pkts = []
		#Query
		pkt = IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="A",seq=seqN,ack=ackN)/query
		pkt.time = tm
		pkts.append(pkt)
		#Seq incremental
		if len(query) == 0:
			seqN = seqN + 1
		else:
			seqN = seqN + len(query)
		#Response
		pkt = IP(dst=srcIp,src=self.dstIp)/TCP(dport=int(self.srcPort),sport=int(self.dstPort),flags="A",seq=ackN,ack=seqN)/response
		pkt.time = tm
		pkts.append(pkt)
		#Acq incremental
		if len(response) == 0:
			ackN = ackN + 1
		else:
			ackN = ackN + len(response)
		return (pkts, seqN, ackN)

	def sendData(self, srcIp, seqN, ackN, data, tm):
		#Query
		pkt = (IP(dst=self.dstIp,src=srcIp)/TCP(dport=int(self.dstPort),sport=int(self.srcPort),flags="A",seq=seqN,ack=ackN)/data)
		pkt.time = tm
		#Seq incremental
		if len(query) == 0:
			seqN = seqN + 1
		else:
			seqN = seqN + len(data)
		return ([pkt], seqN, ackN)


class protocol:
	def __init__(self, serverIp, serverPort):
		self.communication = ipv4Tcp(serverIp, serverPort)

	def http(self, srcIp, url, method, protocol, useragent, referer, param, retCode, tm):
		try:
			#Client query
			_query = "%s %s %s\n" % (method, url, protocol)
			_useragent = "User-Agent: %s\n" % str(useragent)
			_referer = "Referer: %s\n" % str(referer)
			if param == "":
				httpQuery = "%s%s%s\n" % (_query, _useragent, _referer) 
			else:
				_param = "%s\n" % str(param)
				httpQuery = "%s%s%s%s\n" % (_query, _useragent, _referer, _param) 
			#Server Response
			if retCode == "200":
				_response = "%s %s OK" % (protocol, retCode)
			elif retCode == "302":
				_response = "%s %s Found" % (protocol, retCode)
			elif retCode == "400":
				_response = "%s %s Bad Request" % (protocol, retCode)
			elif retCode == "401":
				_response = "%s %s Unauthorized" % (protocol, retCode)
			elif retCode == "403":
				_response = "%s %s Forbidden" % (protocol, retCode)
			elif retCode == "404":
				_response = "%s %s Not Found" % (protocol, retCode)  
			elif retCode == "414":
				_response = "%s %s Request-URI Too Long" % (protocol, retCode)
			elif retCode == "500":
				_response = "%s %s Internal Server Error" % (protocol, retCode)
			else:
				_response = "%s %s Other" % (protocol, retCode)
			if retCode == "200" and (method == "GET" or method == "POST"):
				httpResponse = "%s\n\n<html><head></head><body></body></html>\n\n" % _response
			elif retCode == "302" or retCode == "200":
				httpResponse = "%s\n\n" % _response
			else:
				httpResponse = "%s\nConnection: close\n\n" % _response
			#Initialice connection
			(pkts1, seqN, ackN) = self.communication.handshake(srcIp, tm)
			#Query and response HTTP
			(pkts2, seqN, ackN) = self.communication.queryResponse(srcIp, seqN, ackN, httpQuery, httpResponse, tm)
			#End connection
			pkts3 = self.communication.finishconnection(srcIp, seqN, ackN, tm)
			return (pkts1 + pkts2 + pkts3)
		except:
			sys.stderr.write("Unable to create the following HTTP traffic:\n\nhttpQuery:\n%s\nhttpResponse:\n%s\n-------\n" % (httpQuery, httpResponse))


class log2pcap:
	def __init__(self, logFile, outputFileName, template, serverIp, serverPort, dumpToFile=1):
		self.logFileName = logFile
		try:
			f = open(logFile, 'rb')
			f.close()
		except:
			sys.stderr.write("\n[Error] Log File \"%s\" not found, exit...\n\n" % logFile)
			sys.exit(1)
		self.pcapFileName = outputFileName
		templates = ['apache', 'webseal', 'nginx', 'iis', 'iis-w3c', 'tomcat']
		if template not in templates:
			return None 
		self.template = template
		self.proto = protocol(serverIp, serverPort)
		try:
			self.dumpToFile = int(dumpToFile)
		except:
			return None

	def printData(self):
		print bcolors.FAIL + "\n\t-= Log2Pcap =-" + bcolors.ENDC
		print "\tFile log: " + bcolors.OKBLUE + str(self.logFileName) + bcolors.ENDC
		print "\tPcap file: " + bcolors.OKBLUE + str(self.pcapFileName) + bcolors.ENDC
		print "\tTemplate: " + bcolors.OKBLUE + str(self.template) + bcolors.ENDC
		print "\tDump to Pcap every: " + bcolors.OKBLUE + str(self.dumpToFile) + bcolors.ENDC

	def parseLog(self):
		if self.template == "apache":
			self.processFile("apacheLogLine")
		elif self.template == "iis":
			self.processFile("iisLogLine")
		elif self.template == "iis-w3c":
			self.processFile("iisw3cLogLine")
		elif self.template == "webseal":
			self.processFile("websealLogLine")
		elif self.template == "nginx":
			self.processFile("nginxLogLine")
		elif self.template == "tomcat":
			self.processFile("tomcatLogLine")
		else:
			sys.stderr.write("\n[Error] Unknown template \"%s\", exit...\n\n" % self.template)
			sys.exit(1)

	def processFile(self, typeLog):
		startTime = time.time()
		try:
			logFile = open(self.logFileName, 'r')
		except:
			sys.stderr.write("\n[Error] Log File \"%s\" not found, exit...\n\n" % self.logFileName)
			sys.exit(1)
		try:
			pcapfile = PcapWriter(self.pcapFileName, append=True)
		except:
			sys.stderr.write("\n[Error] Create PCAP file \"%s\" not allowed, exit...\n\n" % self.pcapFileName)
			sys.exit(1)
		methodLogLine = getattr(self, typeLog)
		cont = 0
		nlines = 0
		total = 0
		traffic = []
		print (bcolors.WARNING + "\tStarting:" + bcolors.ENDC)
		for log in logFile:
			try:
				(srcIp, url, method, protocol, useragent, referer, param, retCode, tm) = methodLogLine(log)
			except:
				continue
			traffic = traffic + self.proto.http(srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
			cont = cont + 1
			if cont == self.dumpToFile:
				pcapfile.write(traffic)
				nlines = nlines + cont
				cont = 0
				traffic = []
				if nlines == 10000:
					total = total + 10000
					nlines = 0
					print (bcolors.OKGREEN + "\t\t" + str(total) + " lines processed." + bcolors.ENDC)
		if traffic:
			print (bcolors.OKGREEN + "\t\t" + str(total+cont) + " lines processed." + bcolors.ENDC)
			pcapfile.write(traffic) 
		
		print (bcolors.WARNING + "\tProgram finished after " + str(time.time() - startTime) + " seconds.\n" + bcolors.ENDC)
		logFile.close()
		pcapfile.close()
			
	def apacheLogLine(self, logline):
		try:
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split('"')
			srcIp = zone[0].split(' ')[0]
			tm = zone[0].split(' ')[3].replace('[','')
			tm = time.strptime(tm, "%d/%b/%Y:%H:%M:%S")
			tm = int(time.mktime(tm))
			query = zone[1].split(' ')
			method = str(query[0])
			url = str(query[1])
			protocol = str(query[-1])
			useragent = str(zone[5])
			referer = str(zone[3])
			retCode = str(zone[2].split()[0])
			param = ""			
			if srcIp == "::1":
				srcIp = "127.0.0.1"
			return (srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None

	def tomcatLogLine(self, logline):
		try:
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split('"')
			srcIp = zone[0].split(' ')[0]
			tm = zone[0].split(' ')[3].replace('[','')
			tm = time.strptime(tm, "%d/%b/%Y:%H:%M:%S")
			tm = int(time.mktime(tm))
			query = zone[1].split(' ')
			method = str(query[0])
			url = str(query[1])
			protocol = str(query[-1])
			retCode = str(zone[2].split()[0])
			param = ""			
			if srcIp == "::1":
				srcIp = "127.0.0.1"
			return (srcIp, url, method, protocol, 'Unkown', 'Unkown', param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None

	def iisw3cLogLine(self, logline):
		try:
			#Delete "\n"
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split(' ')
			srcIp = str(zone[2])
			dstIp = str(zone[4])
			referer = str(zone[-1])
			#Some logs have sourcePort... others no! If it has:
			if zone[5].isdigit():
				serverPort = zone[5]
				method = str(zone[6])
				url = str(zone[7])
				retCode = zone[9]
				protocol = str(zone[13])
				useragent = str(zone[14])
			else:
				method = str(zone[5])
				url = str(zone[6])
				retCode = zone[8]
				protocol = str(zone[12])
				useragent = str(zone[13])
			param = ""
			tm = time.strptime(zone[0]+':'+zone[1], "%Y-%m-%d:%H:%M:%S")
			tm = int(time.mktime(tm))
			return (srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None

	def iisLogLine(self, logline):
		try:
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split(', ')
			srcIp = str(zone[0])
			dstIp = str(zone[6])
			method = str(zone[12])
			url = str(zone[13])
			retCode = str(zone[10])
			param = str(zone[14])
			useragent=""
			referer=""
			protocol="HTTP/1.1"
			tm = time.strptime(zone[2]+':'+zone[3], "%m/%d/%y:%H:%M:%S")
			tm = int(time.mktime(tm))
			return (srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None

	def websealLogLine(self, logline):
		try:
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split(' ')
			srcIp = str(zone[0])
			query = logline.split('"')[1].split(' ')
			method = str(query.pop(0))
			protocol = str(query.pop(-1))
			url = str(u''.join(query))
			retCode = zone[len(zone)-2]
			useragent=""
			referer=""
			param = ""
			tm = zone[3].replace('[','')
			tm = time.strptime(tm, "%d/%b/%Y:%H:%M:%S")
			tm = int(time.mktime(tm))
			return (srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None

	def nginxLogLine(self, logline):
		try:
			logline = re.sub(r"[\r\n]+", "", logline)
			zone = logline.split(', ')
			srcIp = zone[0].split(' ')[0]
			zone = logline.split('"')
			query=zone[1].split(' ')
			method = str(query[0])
			url = str(query[1])
			protocol = str(query[-1])
			useragent=str(zone[5])
			referer=str(zone[3])
			retCode = zone[2].split(' ')[1]
			param = ""
			tm = zone[0].split(' ')[3].replace('[','')
			tm = time.strptime(tm, "%d/%b/%Y:%H:%M:%S")
			tm = int(time.mktime(tm))
			return (srcIp, url, method, protocol, useragent, referer, param, retCode, tm)
		except:
			sys.stderr.write("Unable to parse %s\n" % logline)
			return None


class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'


def main():
	templates = ['apache', 'webseal', 'nginx', 'iis', 'iis-w3c', 'tomcat']
	parser = argparse.ArgumentParser(prog='log2pcap', description='Log2Pcap: Server log to Pcap file',)
	parser.add_argument('-l', '--log', required=True, help='server log')
	parser.add_argument('-o', '--output', required=True, help='pcap output file')
	parser.add_argument('-p', '--port', required=True, help='server port')
	parser.add_argument('-s', '--server', help='server ip')
	parser.add_argument('-d', '--dump', help='Every X connections dump to file')
	parser.add_argument('-t', '--template', required=True, help='log server type', choices = templates)
	parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2')
	parser.add_argument('-V', '--verbosity', help='print output', action="store_true")
	args = parser.parse_args()
	if args.verbosity:
		print "Verbosity turned on"
	logFile = args.log
	fileName = args.output
	template = args.template
	serverPort = args.port
	if not args.server:
		serverIp = "127.0.0.1"
	else:
		serverIp = args.server
	if not args.dump:
		dumpToFile = 100
	else:
		try:
			dumpToFile = int(args.dump)
		except:
			sys.stderr.write("Dump option only accept integer value, you provided: %s\n" % args.dump)
			sys.exit(1)
	core = log2pcap(logFile, fileName, template, serverIp, serverPort, dumpToFile)
	if core:
		core.printData()
		core.parseLog()


if __name__ == "__main__":
	main()
