#!/usr/bin/python
import sys
import time
import paramiko
import getpass
import socket
import nmap
from multiprocessing import Pool
from timeit import Timer

subnet = "" #subnet to scan and deploy configuration to


class TerminalColor:
	'''Terminal Color Codes'''
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'


def massConnector(ip):	
	'''Main Connection Interface'''	
	cisco_config = "\n"	# Manual Cisco Configuration (depreciating)
	juniper_config = "set ethernet-switching-options secure-access-port dhcp-snooping-file location /var/log/dhcp_snooping.db\nset ethernet-switching-options secure-access-port dhcp-snooping-file write-interval 120\ncommit\n"	# Manual Juniper Configuration (depreciating)
	
	pre_ssh = paramiko.SSHClient() # Create instance of SSHClient object
	pre_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Define host key policy. 
	#pre_ssh.load_system_host_keys() -> More secure setup. set_missing_host_key_policy() automatically adds missing keys.  POSSIBILITY OF SPOOFING.
	
	try:
		remote_connection = pre_ssh.connect(ip, username=username, password=password) # initiate SSH connection
		if remote_connection is None:
		        print TerminalColor.OKGREEN + "[OK] SSH connection established with " + ip + TerminalColor.ENDC
			remote_connection = pre_ssh.invoke_shell()
			output = remote_connection.recv(1000) # Place received input in empty buffer
			
			router_type = GetRouterType(remote_connection) # Call function for determining router type
			print TerminalColor.OKBLUE + "[Information] Router/Switch for " + ip + " is " + str(router_type) + TerminalColor.ENDC
			
			if router_type == "CISCO":
				DisablePagingCisco(remote_connection)
				PushConfig(remote_connection, cisco_config, router_type)
				print TerminalColor.OKGREEN + "[OK] Configuration pushed to " + ip + TerminalColor.ENDC
			elif router_type == "JUNIPER":
				DisablePagingJuniper(remote_connection)
				PushConfig(remote_connection, juniper_config, router_type)
				print TerminalColor.OKGREEN + "[OK] Configuration pushed to " + ip + TerminalColor.ENDC
			else:
				print TerminalColor.FAIL + "[FAIL] GetRouterType Function for " + ip + " returned unknown value: " + str(router_type) + TerminalColor.ENDC
			
			remote_connection.close() # Gracefully close SSH connection

	except paramiko.AuthenticationException: # Exception for incorrect authentication attempt
		print TerminalColor.FAIL + "[FAIL] Authentication failed with " + ip + TerminalColor.ENDC
	except socket.error, e: # Exception for connectoin failure
		print TerminalColor.FAIL + "[FAIL] Connection error with " + ip + TerminalColor.ENDC


def DisablePagingCisco(remote_connection):
	'''Disabling Cisco Paging Function'''
	remote_connection.send("terminal length 0\n")
	time.sleep(1)
	
	output = remote_connection.recv(1000)
	remote_connection.send("config t\n")
	output = remote_connection.recv(1000)

	return None


def DisablePagingJuniper(remote_connection):
        '''Disabling Juniper Paging Function'''
        remote_connection.send("set cli screen-length 0\n")
        time.sleep(1)

        output = remote_connection.recv(1000)
	remote_connection.send("edit\n")
        output = remote_connection.recv(1000)

        return None


def GetRouterType(remote_connection):
	'''Discover Router Type'''
	remote_connection.send("show version\n")
	time.sleep(2)
	remote_connection.send("q\b")	# Sending single character 'q' and backspace allow for you to cancel out the previous command
	output = remote_connection.recv(20000)
	output = output.lower()

	if "cisco" in output.lower():
        	return "CISCO"
	elif "junos" in output.lower():
		return "JUNIPER"
	else:
		return None


def PushConfig(remote_connection, config, router):
	'''Push Configuration'''
	if router == "CISCO":
		remote_connection.send(config)
		time.sleep(12)
	elif router == "JUNIPER":
		remote_connection.send(config)
		time.sleep(14)
	else:
		pass

	output = remote_connection.recv(1000000)
	print output

	return None


def GetCreds():
	'''Get Credentials for Connection'''
	username = str(raw_input("Username:"))
	password = getpass.getpass()

def GetRawConfigInput():
	'''Configuration Input'''
	configuration = []
	print "Input text:"
	print "ctrl-D signals end of input"
	while True:
		try:
			configuration_raw = raw_input()
		except EOFError:
			break
		configuration.append(configuration_raw)
	
	print "\n" + '\n'.join(configuration)
	
	return None


pool = Pool()
alive = []

GetCreds()

nm = nmap.PortScanner()
nm.scan(hosts=subnet, arguments="-n -sS -p 22")

for alive_host in nm.all_hosts():
	alive.append(alive_host)

print TerminalColor.HEADER + "[START] Hosts identified as 'UP' by nmap " + str(alive[:]) + TerminalColor.ENDC

results = pool.map(massConnector, alive)
