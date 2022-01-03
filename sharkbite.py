#    _____ __               __   ____  _ __     
#   / ___// /_  ____ ______/ /__/ __ )(_) /____ 
#   \__ \/ __ \/ __ `/ ___/ //_/ __  / / __/ _ \
#  ___/ / / / / /_/ / /  / ,< / /_/ / / /_/  __/
# /____/_/ /_/\__,_/_/  /_/|_/_____/_/\__/\___/   
#
#  Authors:
#    - Anirudha Kanodia
#    - Borui Li
#    - Junheng (George) Wang

from scapy.all import *
import sys
import argparse
import re
import socket
import requests
from bs4 import BeautifulSoup
import json
import datetime
from socket import getservbyport
from bs4 import BeautifulSoup
import urllib.parse
import ipaddress

MAX_PORT = 65535
TIMEOUT = 2

class CVE():

	def __init__(self):
		self.cve = ""
		self.link = ""
		self.serviceName = ""


class ScanResults():
	'''
	A clean way to store the results from a scan so the output
	is displayed in a standardized format.
	'''

	def __init__(self):
		self.open_ports = []
		self.closed_ports = []
		self.closed_ports_ss = []
		self.filtered_ports = []
		self.unfiltered_ports = []
		self.unknown_ports = []
		self.open_ports_ss = []
		self.unanswered = []
		self.ip = ""

	def add_open_port(self, port):
		self.open_ports.append(port)
	
	def add_open_port_ss(self, port):
		self.open_ports_ss.append(port)

	def add_closed_port(self, port):
		self.closed_ports.append(port)
	
	def add_closed_port_ss(self, port):
		self.closed_ports_ss.append(port)

	def add_filtered_port(self, port):
		self.filtered_ports.append(port)

	def add_unfiltered_port(self, port):
		self.unfiltered_ports.append(port)

	def add_unknown_port(self, port):
		self.unknown_ports.append(port)
	
	def add_unanswered (self, port):
		self.unanswered.append(port)
	
	def assign_ip (self, ip):
		self.ip = ip

	def print_scan_results(self, short=False, detect_cves=False):

		for port in self.open_ports:
			print("Port " + str(port) + " is Open")

		# Don't print any more output if the short mode response is enabled
		if short:
			return

		for port in self.closed_ports:
			print("Port " + str(port) + " is Closed")

		for port in self.filtered_ports:
			print("Port " + str(port) + " is Filtered")

		for port in self.unfiltered_ports:
			print("Firewall on port " + str(port) + " unfiltered")

		for port in self.unknown_ports:
			print("Unknown response on " + str(port))

		port_to_cves = dict()

		for port in self.open_ports_ss:
			banner = get_banner(self.ip, port)

			try:
				port_name = getservbyport(port)
			except:
				port_name = get_service(banner)

			version = get_version(banner)

			if detect_cves:
				cves = get_api(version)
				
				if len(cves) == 0:
					'no cve'

				else:
					for cve_i in cves:
						cve_instance = CVE()
						cve_instance.cve = cve_i
						URL = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="
						cve_instance.link = URL + urllib.parse.quote(version)
						cve_instance.serviceName = version
						port_to_cves[port] = cve_instance


			print('{}{}{}{}'.format(str(port).ljust(9), 
				"\033[92m {}\033[00m".ljust(19).format("Open"), 
				port_name.ljust(19), 
				"\033[96m {}\033[00m".format(version)))

		if len(port_to_cves) > 0:
			print("\nCVES DETECTED\n")
			print('{}{}{}{}'.format("PORT".ljust(10), 'VERSION'.ljust(25), "CVE".ljust(20), "LINK", ))

			for i in port_to_cves:
				print('{}{}{}{}'.format(str(i).ljust(9), 
					"\033[96m {}\033[00m".ljust(17).format(port_to_cves[i].serviceName), 
					"\033[91m {}\033[00m".ljust(19).format(port_to_cves[i].cve), 
					port_to_cves[i].link))



def TCP_SYN_SCAN(dst_ip, ports, show, ss=False):
	'''
	Arguments:
		dst_ip: Destination IP to scan
		ports: Ports that need to be scanned
	Return:
		ScanResult object containing the results of the scans

	Perform a TCP SYN scan on the given target. This scan does not establish a TCP connection with the
	target but rather just sends the SYN packet in the 3-way handshake. This type of scan is relatively
	stealthy and fast.
	'''
	src_port = RandShort()
	results = ScanResults()

	for port in ports:
		if (show == True):
			print("\nChecking Port: " + str(port))

		tcp_syn_scan_packet = sr1(IP(dst = dst_ip)/TCP(sport = src_port,dport = port, flags = "S"), timeout=TIMEOUT, retry=1, verbose=False)

		if tcp_syn_scan_packet == None:
			results.add_unanswered(port)
		else:
			if tcp_syn_scan_packet.haslayer("TCP"):

				
				# Port is closed
				if tcp_syn_scan_packet[TCP].flags == 0x14:

					if (show == True):
						results.add_closed_port(port)
					if (ss == True):
						results.add_closed_port_ss(port)

				# Port is open
				elif tcp_syn_scan_packet[TCP].flags == 0x12:
					if (not ss): 
						results.add_open_port(port)
					else: 
						results.add_open_port_ss(port)
						results.assign_ip(dst_ip)
				# Port is filtered
				else:
					results.add_filtered_port(port)

			# Port is filtered		
			elif tcp_syn_scan_packet.haslayer("ICMP"):
				results.add_filtered_port(port)

			# Unknown response received
			else:
				print(tcp_syn_scan_packet.summary())
				results.add_unknown_port(port)

	return results




def TCP_CON_SCAN(dst_ip, ports, show, ss=False):
	'''
	Arguments:
		dst_ip: Destination IP to scan
		ports: Ports that need to be scanned
	Return:
		ScanResult object containing the results of the scans

	Perform a TCP Connect scan on the given target. This scan establishes a TCP connection with the
	target by completing the 3-way handshake. This scan is more time consuming and more intrusive than
	the TCP SYN scan.
	'''
	src_port = RandShort()
	results = ScanResults()

	for port in ports:
		if (show == True):
			print("\nChecking Port: " + str(port))

		tcp_con_scan_packet = sr1(IP(dst = dst_ip)/TCP(sport = src_port,dport = port, flags = "S"), timeout=TIMEOUT, retry=1, verbose=False)
		if (tcp_con_scan_packet == None):
			results.add_unanswered(port)
		elif(tcp_con_scan_packet.haslayer('TCP')):

			# 0x12 = 10010: ACK and SYN, connection is open
			if (tcp_con_scan_packet.getlayer('TCP').flags == 0x12):
				send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port, dport=port, flags="AR"), timeout=TIMEOUT, retry=1, verbose=False)
				if (not ss): 
					results.add_open_port(port)
				else:
					results.add_open_port_ss(port)

			# 0x14 = 10100: ACK and RST, connection is terminated
			if (tcp_con_scan_packet.getlayer('TCP').flags == 0x14):
				if (show == True):
					results.add_closed_port(port)
		else:
			if (show == True):
				results.add_closed_port(port)

	return results


def TCP_ACK_SCAN(dst_ip, ports, show):
	'''
	Arguments:
		dst_ip: Destination IP to scan
		ports: Ports that need to be scanned
	Return:
		ScanResult object containing the results of the scans

	Perform a TCP ACK scan on the given target. This scan does not establish a TCP connection with the
	target but rather just sends the ACK packet in the 3-way handshake. It works differently compared to the 
	TCP SYN scan and TCP Connect scan and is particularly useful when there is a firewall involved, to determine
	if the firewall is stateful or not and identifying filtered ports. Open and closed ports both send back a
	RST response.
	'''

	results = ScanResults()

	for port in ports:
		if (show == True):
			print("\nChecking Port: " + str(port))

		tcp_ack_scan_packet = sr1(IP(dst = dst_ip)/TCP(dport = port, flags = "A"), timeout=TIMEOUT, retry=1, verbose=False)
		if (tcp_ack_scan_packet == None):
			results.add_unanswered(port)
		elif (tcp_ack_scan_packet.haslayer('TCP')):

			# 0x4 = 00010: RST, no firewall
			if (tcp_ack_scan_packet.getlayer('TCP').flags == 0x4):
				if (show == True):
					results.add_unfiltered_port(port)

			# check if there is an ICMP layer
			elif (tcp_ack_scan_packet.haslayer('ICMP')):

				# check type
				if (tcp_ack_scan_packet.haslayer('ICMP').type == 3):

					# check code
					if (tcp_ack_scan_packet.haslayer('ICMP').code in [1,2,3,9,10,13]):	
						results.add_filtered_port(port)
		else:
			print ("Firewall on " + str(port) + " is filtered and present")
			results.add_filtered_port(port)

	return results


def UDP_SCAN(dst_ip, ports, verbose):
	'''
	Arguments:
		dst_ip: Destination IP to scan
		ports: Ports that need to be scanned
		verbose: Whether unopen ports need to be shown
	Return:
		ScanResult object containing the results of the scans

	Perform a UDP scan on the given target. Assigns the state of the port based
	on the response received. These scans are often overlooked while testing,
	however are important while conducting any tests.
	'''
	results = ScanResults()

	for port in ports:

		if (verbose):
			print("\nChecking Port: " + str(port))

		udp_scan_packet = sr1(IP(dst = dst_ip)/UDP(sport=port, dport=port), timeout=TIMEOUT, verbose=False)

		if udp_scan_packet == None:
			results.add_unanswered(port)

		else:

			if udp_scan_packet.haslayer("ICMP"):
				if verbose:
					results.add_closed_port(port)

			elif udp_scan_packet.haslayer("UDP"):
				results.add_unfiltered_port(port)

			else:
				if verbose:
					results.add_unknown_port(port)

					print(udp_scan_packet.summary())

	return results


def get_common_ports(UDP=False):
	'''
	Arguments:
		UDP: Get top 1000 UDP ports. Default is top 1000 TCP ports.
	Returns:
		ports: A list of top 1000 TCP/UDP ports
	Gets the top 1000 ports for TCP/UDP
	'''

	if not UDP:
		filename = 'tcp_top_1000_ports.txt'
	else:
		filename = 'udp_top_1000_ports.txt'

	with open(filename, 'r') as file:
		ports = file.readline()

	return parse_ports(ports)



def discover_hosts(ip_range, interface):
	'''
	Arguments:
	  ip_range: The IP or IP range to perform an arp scan on
	  interface: The target interface
	Find the IP and MAC address(es) for the given IP/IP range that are currently active.
	'''

	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=TIMEOUT, retry=2, iface=interface, verbose=False)

	nodes = []
	for sent, received in ans:
		node = {"IP": received.psrc, "MAC": received.hwsrc}
		nodes.append(node)

	print('{}{}'.format("IP".ljust(20), 'MAC', ))

	for node in nodes:
		print('{}{}'.format(str(node["IP"]).ljust(20), node["MAC"], ))


def service_scan(ip, ports):
	'''
	Arguments:
		ip: The IP address to perform the scan on
		ports: The ports to conduct the scan on
	
	Performs a service scan to determine the services running behind
	ports. If a service is identified, the program additionally checks
	whether the service running has a CVE assigned to it (indicating it's vulnerable).
	and if so, reports the same. 
	'''

	print(ip)
	date = datetime.datetime.now()

	print("Starting Service Scan at " + str(date))
	print("Service Scan report for " + ip)
	
	# Check for ping latency
	t0 = time.perf_counter()
	ping = sr1(IP(dst = ip) / ICMP(),verbose=False, timeout=TIMEOUT)
	t1 = time.perf_counter()

	# Check if host is up
	if (ping != None):
		print("Host is up (" + str(round((t1 - t0),5)) + "s latency).")
	else:
		print("Host is down")
		return

	# Get open ports
	results = TCP_SYN_SCAN(ip, ports, False, True)

	# Print all port info
	print("Not shown: " + str(len(results.closed_ports_ss)) + " closed ports")
	print('{}{}{}{}'.format("PORT".ljust(10), 'STATE'.ljust(10), "SERVICE".ljust(20), "VERSION"))

	results.print_scan_results(detect_cves=True)

	# Get MAC address
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=TIMEOUT, retry=1, verbose=False)

	for sent, received in ans:
		print("MAC Address: "+ str(received.hwsrc))
		


def get_banner(ip, port):
	'''
	Arguments:
		ip: The IP address of the target machine
		ports: The ports to grab the banner of
	
	Grab the banner of a service running behind a port
	'''

	service_version = ""

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(TIMEOUT)
		s.connect((ip, port))

		try:
			headers = \
					"GET / HTTP/1.1\r\n" \
					f"Host: {ip}\r\n" \
					"User-Agent: sharkbite\r\n" \
					"Accept-Encoding: gzip, deflate\r\nAccept: */*\r\n" \
					"Connection: keep-alive\r\n\r\n"

			s.send(headers.encode())
			banner = s.recv(1024)
			s.close()

			if (len(banner) < 10):
				service_version = b'[0] cannot get the version'
			else:
				service_version = banner

			return service_version

		except:
			service_version = b'[0] cannot get the version'
			return service_version
			
	except:
		service_version = b'[-1] cannot reach port'
		return service_version
		

def get_service(banner):
	'''
	Arguments:
		banner: The banner being parsed
	
	Parse the banner for relevant information about the service. 
	'''

	service = ""
	try:
		banner = banner.decode()
	except Exception as e:
		e = str(e)
		new_banner_len = (int(e[e.find("position")+9:e.find(":")]))
		banner = banner[:new_banner_len].decode()

	if "[0]" in banner:
		return service

	elif "[1]" in banner:
		return service

	elif "HTTP" in banner or "http" in banner:
		service = "http"

	elif "VMware" in banner:
		if "SSL" in banner:
			service = "ssl/vmware-auth"
		else:
			service = "vmware-auth"

	elif "SSH" in banner:
		service = "SSH"

	elif "FTP" in banner:
		version = banner[:banner.find("\r\n")]

	else:
		service = ""

	return service


def get_version(banner):
	'''
	Arguments:
		banner: The banner being parsed
	
	Parse the banner to extract the version of the service running
	behind a port.
	'''

	version = ""

	try:
		banner = banner.decode()

	except Exception as e:
		e = str(e)
		new_banner_len = (int(e[e.find("position")+9:e.find(":")]))
		banner = banner[:new_banner_len].decode()

	if "[0]" in banner:
		return version

	elif "[1]" in banner:
		return version

	elif "HTTP" in banner:

		if "Server:" in banner:
			banner = banner[banner.find("Server:")+8:]
			version = banner[:banner.find("\r\n")]

		elif "<title>" in banner:
			banner = banner[banner.find("<title>")+7:]
			version = banner[:banner.find("</title>")]

	elif "VMware" in banner:
		banner_list = banner.split(",")

		if "SSL" in banner:
			version = (banner_list[0][:banner_list[0].find(":")] + 
					  "(Uses " + banner_list[2][banner_list[2].find(":")+1:] + 
					  ", " + banner_list[1][banner_list[1].find(":")+1:] + ")")

		else:
			version = (banner_list[0] + "(Uses " + banner_list[2][banner_list[2].find(":")+1:] + 
					  ", " + banner_list[1][banner_list[1].find(":")+1:] + ")")

	elif "SSH" in banner:
		version = banner[:banner.find("\r\n")]
	else:
		version = banner

	return version



def is_valid_port(port):
	'''
	Arguments:
		port: The port being validated
	Returns:
		True if the port is valid and False otherwise
	Determines if the given port is valid.
	'''

	if 0 <= port <= MAX_PORT:
		return True

	return False

def is_valid_ip(ip):
	'''
	Arguments:
		ip: The IP being validated
	Returns:
		True if the IP is valid and False otherwise
	Determines if the given IP is valid.
	'''

	try:
		# An error is thrown if the ip is invalid
		ipaddress.ip_address(ip)
		return True

	except:
		return False


def parse_ports(arg):
	'''
	Arguments:
		arg: The arguments that need to be parsed
	Returns:
		result: A list of parsed ports
	Parses the command line arguments to create a list of ports
	'''
	result = []

	ports = arg.split(",")
	for p in ports:
		r = p.split("-")

		# A single port
		if len(r) == 1:

			if is_valid_port(int(p)):
				result.append(int(p))

		# Port range
		else:
			start, end = r
			start = int(start)
			end = int(end)

			if is_valid_port(start) and is_valid_port(end) and start <= end:
				for j in range(start, end+1):
					result.append(j)

	return result


def get_api(service):
	'''
	Arguments:
		service: The service being checked for vulnerabilities
	Returns:
		lst_cve: The CVE number of the service version if it is vulnerable
		lst_severity: The severity level of the vulnerable service
		lst_exploit: The CVSS score for the vulnerable service
	Parses the command line arguments to create a list of ports
	'''

	name = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?'
	site = name + 'keyword=' + urllib.parse.quote(service)

	r = requests.get(site)
	soup = BeautifulSoup(r.content, "html.parser")

	table = soup.find(id="TableWithRules")

	out = []
	for row in table.findAll("tr"):
			info = row.findAll("td")
			col = [val.text.strip() for val in info]
			out.append([val for val in col if val]) 


	cves = []
	for i in out:
		if i and len(i) > 0:
			cves.append(i[0])

	if len(cves) > 2:
		cves = cves[:2]

	return cves


if __name__ == '__main__':

	parser = argparse.ArgumentParser(prog="python3 sharkbite.py")
	parser.add_argument("-p", help="Comma seperated ports to scan. If not specified, scan the 1000 most common ports. "
									+ "Port ranges can be used as well. For exaxmple: 10-20", type=parse_ports)
	parser.add_argument("-i", "--interface", help="Interface to perform the scan on", default=None)
	parser.add_argument("-a", help="Show all ports even ones that are unreable or closed", default=True)

	# Scans
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-sS", help="Perform TCP SYN scan", action="store_true")
	group.add_argument("-sT", help="Perform TCP Connect scan", action="store_true")
	group.add_argument("-sA", help="Perform TCP ACK scan", action="store_true")
	group.add_argument("-sU", help="Perform UDP scan", action="store_true")
	group.add_argument("--discover-hosts", help="Discover hosts in LAN by performing an ARP scan", action="store_true")
	group.add_argument("--service-scan", help="Detect the services and versions on an IP", action="store_true")
	
	parser.add_argument("target", type=str, nargs="?", help="Target being scanned", default=None)	


	args = parser.parse_args()
		
	# No arguments passed in, display usage.
	if len(sys.argv[1:]) == 0:
		parser.print_help()
		exit()
	
	
	# Handle scans
	if args.sS:
		if args.target == None or not is_valid_ip(args.target):
			print("Please specify a valid target for the scan")
			exit()

		ports = args.p
		verbose = True
		if not ports:
			ports = get_common_ports()
			verbose = False

		
		scan_result = TCP_SYN_SCAN(args.target, ports, args.a)
		scan_result.print_scan_results(short=not verbose)


	if args.sT:
		if args.target == None or not is_valid_ip(args.target):
			print("Please specify a valid target for the scan")
			exit()

		ports = args.p
		verbose = True
		if not ports:
			ports = get_common_ports()
			verbose = False


		scan_result = TCP_CON_SCAN(args.target, ports, args.a)
		scan_result.print_scan_results(short=not verbose)


	if args.sA:
		if args.target == None or not is_valid_ip(args.target):
			print("Please specify a valid target for the scan")
			exit()
		
		ports = args.p
		verbose = True
		if not ports:
			ports = get_common_ports()
			verbose = False

		scan_result = TCP_ACK_SCAN(args.target, ports, args.a)
		scan_result.print_scan_results(short=not verbose)

	if args.sU:
		if args.target == None or not is_valid_ip(args.target):
			print("Please specify a valid target for the scan")
			exit()

		ports = args.p
		verbose = True
		if not ports:
			ports = get_common_ports(UDP=True)
			verbose = False

		scan_result = UDP_SCAN(args.target, ports, args.a)
		scan_result.print_scan_results(short=not verbose)


	if args.discover_hosts:
		if args.target == None :
			print("Please specify a target to scan. Example: python3 sharkbite.py --discover-hosts 10.0.0.1/24")
			exit()
		elif args.interface == None:
			print("Please specify a target interface")
			exit()
		else:
			discover_hosts(args.target, args.interface)

	if args.service_scan:
		if args.target == None or not is_valid_ip(args.target):
			print("Please specify a valid target to scan. Example: python3 sharkbite.py --service_scan 10.0.0.1")
			exit()

		ports = args.p
		if not ports:
			ports = get_common_ports()
		
		service_scan(args.target, ports)

	exit()
