#!/usr/bin/env python
# -*- coding: utf-8 -*-
from time import strftime, sleep
from nmap import PortScanner
from requests import post
from re import findall
from os import system
from sys import argv

bold = "\033[1m"
underline = "\033[4m"
green = "\033[92m"
blue = "\033[94m"
yellow = "\033[93m"
red = "\033[91m"
endcolor = "\033[0m"

portlist = [80]

def logo():
	system("clear")
	print bold+"\t\t\tKing Cobra | Web Analysis Tool"+endcolor
	print bold+"\t\t\t------------------------------"+endcolor
	print "\t\t\t--==[     {}Turkz Grup{}     ]==--".format(green,endcolor)
	print "\t\t\t--==[       {}Ar-Ge{}        ]==--".format(blue,endcolor)
	print "\t\t\t--==[      {}esw0rmer{}      ]==--".format(yellow, endcolor)
	print bold+"\t\t\t------------------------------"+endcolor


def nmapScan(target):
	nm = PortScanner()
	sc = nm.scan(hosts=target, arguments="-n -T4 -sV -p 21,22,23,25,53,80,110,143,443,465,995,993,1248,1433,3306,3389")
	global siteIP
	siteIP = sc["scan"].keys()[0]
	key, value, total = sc["scan"][siteIP]["tcp"].keys(), sc["scan"][siteIP]["tcp"].values(), len(sc["scan"][siteIP]["tcp"].keys())
	print bold+"Port\t\tName\t\tVersion\t\tStatus"+endcolor
	print "----\t\t------\t\t----\t\t-------"
	for port in range(total):
		if value[port]["state"] == "open":
			portlist.append(key[port])
		else:
			pass
		print "{}\t\t{}\t\t{}\t\t{}".format(key[port], value[port]["name"], value[port]["version"], value[port]["state"])
	print ""
	print "Scan Time     : {}".format(sc["nmap"]['scanstats']['timestr'])
	print "Scan Interval : {}".format(sc["nmap"]['scanstats']['elapsed'])

def exploitScan():
	for port in portlist:
		print "{}Exploits For Port {}{}:\n\thttp://www.enigmagroup.org/exploits/rport/{}/".format(bold+blue,port,endcolor, port)

def adminScan(target):
	def wpScan():
		try:
			payload = post("http://"+target+"/wp-login.php")
			if "Powered by WordPress" in payload.text:
				return True
			else:
				return False
		except:
			return False

	def joomlaScan():
		try:
			payload = post("http://"+target+"/administrator")
			if "Joomla!" in payload.text:
				return True
			else:
				return False
		except:
			return False

	def mybbScan():
		try:
			payload = post("http://"+target+"/admin")
			if "MyBB Group" in payload.text:
				return True
			else:
				return False
		except:
			return False

	if wpScan() == True:
		print bold+"Script: "+green+"WordPress"+endcolor
	if joomlaScan() == True:
		print bold+"Script: "+green+"Joomla!"+endcolor
	elif mybbScan() == True:
		print bold+"Script: "+green+"MyBB"+endcolor
	else:
		print red+bold+"Script Not Found.."+endcolor

def reverseIP(target):
	payload = post("http://viewdns.info/reverseip/?host="+target+"&t=1")
	results = findall('<td>(.*?)</td><td align="center">(.*?)</td></tr><tr>', payload.text)
	for result in results:
		site, date = result
		if len(site) < 50:
			print bold+blue+"Site: "+endcolor+site
			sleep(0.1)
		else:
			pass

if len(argv) == 2:
	logo()
	print bold+yellow+"[*] Checking If < "+endcolor+argv[1]+bold+yellow+" > Is Vulnerable"+endcolor
	print "~"*50
	print bold+yellow+"Start Time: "+endcolor+strftime("%H:%M:%S")+"\t\t\t"+strftime("%d/%m/%Y")
	print "~"*50
	print bold+green+"\t\t<<< Port Scan >>>"+endcolor
	nmapScan(argv[1])
	print bold+green+"\t\t<<< Port Exploit Scan >>>"+endcolor
	exploitScan()
	print bold+green+"\t\t<<< Script Scan >>>"+endcolor
	adminScan(argv[1])
	print bold+green+"\t\t<<< Reverse IP Lookup >>>"+endcolor
	reverseIP(argv[1])
	print "~"*50
	print bold+yellow+"Finish Time: "+endcolor+strftime("%H:%M:%S")+"\t\t\t"+strftime("%d/%m/%Y")
	print "~"*50

else:
	logo()
	print "How To Usage?"
	print "\t"+bold+red+"root@linux"+endcolor+":"+bold+blue+"~/coderlab"+endcolor+"#"+" python "+argv[0]+" target.com"
	raw_input()
