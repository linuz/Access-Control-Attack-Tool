import binascii
import socket
import time

device_list = []
linear_controllers = []
#Do not detect our own IP addresses
device_blacklist = ["127.0.0.1", socket.gethostbyname(socket.gethostname()), socket.gethostbyname(socket.getfqdn())]

def locate_devices():
	udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	udp_socket.settimeout(5)
	udp_socket.bind(('0.0.0.0', 55954))
	udp_socket.sendto( '0201060092da000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'.decode('hex'), ( "255.255.255.255", 55954 ))
	try:
		while 1:
			msg, addr = udp_socket.recvfrom(1024)
			found_device = str(addr[0])
			if not (found_device in device_blacklist):
				device_blacklist.append(found_device)
				device_list.append(found_device)
				print "[!] Device found at " + found_device
				#print msg
	except socket.timeout:
		udp_socket.close()
		return

def detect_linear(devices):
		for i in devices:
			print "[-] Checking " + i
			try:
				linear_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				linear_socket.settimeout(5)
				linear_socket.connect((i, 4660))
				linear_socket.send(binascii.a2b_hex("5AA5000A11013635343332319A71"))
				time.sleep(4)
				response = binascii.b2a_hex(linear_socket.recv(1024))
				#print response
				if "5aa50004110c4625" in response:
					print "[!] " + i + " is a Linear Access Controller with the default password!"
					linear_controllers.append(i + "*")
				elif "5aa50005110d024c23" in response:
					print "[!] " + i + " is a Linear Access Controller"
					linear_controllers.append(i)
				elif "5aa50005110d017eb8" in response:
					print "[!] " + i + " is a Linear Access Controller"
					linear_controllers.append(i)
				else:
					print "[-] " + i + " is unknown"
				linear_socket.close()
			except Exception as e:
				print e
				linear_socket.close()
				continue

print """
====================================================================
	ACAT - Access Control Attack Tool - Detect Linear Controllers
	By: Dennis Linuz <dennismald@gmail.com>

====================================================================
"""
locate_devices()
if device_list:
	detect_linear(device_list)
print ""
print "Linear Access Controllers:"
print "~~~~~~~~~~~~~~~~~~~~~~~~~"
for i in linear_controllers:
	print i
