#!/usr/bin/env python

################################################################################
#
# A poorly written Slack integration that enables adding 
# IP addresses to a Palo Alto dynamic blacklist located on a remote server.
#
# Curently built to run from /opt/blockip/
# 
# https://github.com/ecapuano/slackbot
#
################################################################################

import bottle 
import re
import requests
import json
import socket
import config
import logging
import os
import time
import subprocess

debug = "no" # set to 'yes' to print messages to console

working_dir = "/opt/blockip"
logging.basicConfig(filename='blacklist.log',format='%(asctime)s %(message)s',level=logging.INFO)
logging.info('Application started. Listening on port: %s',config.listen_port)

BLfile = "%s/ipv4bl.txt" % working_dir

app = application = bottle.Bottle()


@app.route('/', method='POST')
def slack_post():
	body = bottle.request.body.read()
	token = bottle.request.forms.get('token')
	team_id = bottle.request.forms.get('team_id')
	team_domain = bottle.request.forms.get('team_domain')
	service_id = bottle.request.forms.get('service_id')
	channel_id = bottle.request.forms.get('channel_id')
	channel_name = bottle.request.forms.get('channel_name')
	timestamp = bottle.request.forms.get('timestamp')
	user_id = bottle.request.forms.get('user_id')
	user_name = bottle.request.forms.get('user_name')
	args = bottle.request.forms.get('text')
	trigger_words = bottle.request.forms.get('trigger_words')
	response_url = bottle.request.forms.get('response_url')

	if token != config.slack_token:  # integration token
		print "INVALID REQUEST RECEIVED! --> %s" % body
		logging.warning('Invalid Request Received %s', body)
		return "LOL NOPE"

	if channel_id != config.authorized_channel:
		logging.warning("Request received from wrong channel: %s",channel_name)
		message = "Request denied for %s. You must send this request from the proper channel." % user_name
		status = "fail"
		sendToSlack(status,message,response_url)
		return "LOL NOPE"

	logging.debug('Incoming request: %s', body)

	logging.info('Blacklist request received from user: %s - contents: %s', user_name, args)

	if (args):
		message = ""
		status = ""
		parseArguments(args,response_url,user_name,timestamp,channel_name)
	else:
		if debug == "yes":
			print "No IP address specified"
		message = "You must specify a single IPv4 address to block."
		logging.warning('Invalid query passed by user: %s -- %s', user_name, args)
		status = "fail"
		sendToSlack(status,message,response_url)


def parseArguments(args,response_url,user_name,timestamp,channel_name):
	#args = "block unblock check | ip domain | notes"
	logging.debug('Starting parseArguments with args: %s',args)
	argList = args.split()
	numargs = len(argList)
	if numargs < 3:
		message = "Wrong number of arguments! Need at least 3, you sent %s" % numargs
		message = message + "\n" + "example: `/blockip block 69.89.31.115 because its bad"
		status = "fail"
		sendToSlack(status,message,response_url)
	else:
		func = argList[0]
		ip = argList[1]
		notes = argList[2:]
		notes = " ".join(notes)
		message = ""

		logging.debug('Arugments extracted - function: %s ip:%s notes:%s',func,ip,notes)

		if func == "block":
			logging.info('Block function requested. Routing')
			blacklistAdder(ip,message,response_url,user_name,timestamp,notes)
		elif func == "unblock":
			logging.info('UN-block function requested. Routing')
			message = "This feature not yet implemented"
			status = "fail"
			sendToSlack(status,message,response_url)
		elif func == "check":
			logging.info('Check function requested. Routing')
			message = "This feature not yet implemented"
			status = "fail"
			sendToSlack(status,message,response_url)
		else:
			logging.warning('Invalid command received from %s: %s',user_name,args)
			message = "Command not valid: %s" % argList[0] + "\n"
			message = message + "Please use `block <ip or domain>` or `check <ip or domain>` or `unblock <ip or domain>`."
			status = "fail"
			sendToSlack(status,message,response_url)


def notDuplicate(ip):
	logging.debug('Running notDuplicate against: %s',ip)
	if ip in open(BLfile).read(): # check to see if IP already exists in the blacklist
		return False
	else:
		return True

def notWhitelisted(ip):
	logging.debug('Running notWhitelisted against: %s',ip)
	if ip not in config.whitelist: # check to see if this domain is already sinkholed by the Palo
		logging.info('IP address is not in whitelist.')
		return True
	else:
		logging.info('IP address is whitelisted!')
		return False


def blacklistAdder(ip,message,response_url,user_name,timestamp,notes):
	logging.debug('Running blacklistAdder with args: %s %s %s %s %s %s',ip,message,response_url,user_name,timestamp,notes)
	if isValidIPv4(ip): # make sure the IP address is valid
		blocked_url = "none"
		addIPtoBL(ip,blocked_url,response_url,user_name,notes)
	elif isURL(ip): # see if IP address is actually a URL
		blocked_url = ip
		ip = isURL(ip)
		addIPtoBL(ip,blocked_url,response_url,user_name,notes)
	else:
		print "Invalid IPv4!!! Aborting..."
		message = "%s is not a valid IPv4 address or URL! Please try again, %s" % (ip, user_name)
		status = "fail"
		sendToSlack(status,message,response_url)



def isValidIPv4(ip):
	logging.debug('Running isValidIPv4 against: %s',ip)
	pattern = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", re.VERBOSE | re.IGNORECASE)
	if pattern.match(ip):
		logging.info('Address is valid IPv4: %s',ip)
		return True
	else:
		logging.warning('Not valid IPv4: %s',ip)
		return False


def isURL(url):
	logging.debug('Running isURL against: %s',url)
	try:
		target_ip = socket.gethostbyname(url)
		socket.inet_aton(target_ip)
		ip = target_ip
		logging.info('URL:%s succesfully converted to IPv4 address:%s',url,ip)
		if isValidIPv4(ip):
			return ip
		else:
			logging.warning('URL does NOT resolve to IPv4 address: %s',url)
			return False
	except socket.error:
		logging.warning('URL does NOT resolve to IPv4 address: %s',url)
		return False


def addIPtoBL(ip,blocked_url,response_url,user_name,notes):
	logging.debug('Running addIPtoBL with args: %s %s %s %s %s',ip,blocked_url,response_url,user_name,notes)
	message = ""
	if notDuplicate(ip):
		if notWhitelisted(ip):
			logging.info('Dupe check complete. No duplicates for: %s',ip)
			timestamp = (time.strftime("%m/%d/%Y %H:%M:%S"))
			blacklist_entry = "%s # from url:%s -- added via Slack by %s on %s -- notes: %s" % (ip,blocked_url,user_name,timestamp,notes)
			logging.info('Blacklist entry generated: %s',blacklist_entry)
			message = "IP:%s (URL:%s) has been added to the PA-7050 Dynamic Blacklist by %s. Reason: %s" % (ip,blocked_url,user_name,notes)
			message = message + "\n" + "Verify your entry here %s" % config.ipbl_location
			with open(BLfile, "a") as workingBLfile:
				workingBLfile.write(blacklist_entry + "\n")
			logging.info('Blacklist entry added to local working list.')
			
			last_entry = subprocess.check_output(['tail', '-1', BLfile])
			logging.debug('Cat last line of local working list:%s',last_entry)

			os.system("scp -i %s %s %s" % (config.ssh_key,BLfile,config.remote_location))
			logging.info('Local blacklist has been SCP\'d to production blacklist')
			status = "pass"
		else:
			message = "`NOTICE!` IP:%s (URL:%s) is on the whitelist and cannot be blocked!" % (ip,blocked_url)
			status = "fail"
			logging.warning('Whitelist entry Detected, not adding: %s',ip)

	else:
		message = "`NOTICE!` IP:%s (URL:%s) requested by %s is already on the blacklist!" % (ip,blocked_url,user_name)
		status = "fail"
		logging.warning('Duplicate entry Detected, not adding: %s',ip)
	sendToSlack(status,message,response_url)


def sendToSlack(status,message,response_url):
	logging.debug('Beginning sendToSlack with args: %s %s %s',status,message,response_url)
	url = response_url
	response_channel = config.response_channel
	data = {"username": config.bot_name, "text": message}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

	if status == "fail":
		r = requests.post(url, data=json.dumps(data), headers=headers) # this sends the response to the user privately about the failure
		logging.info('Failure detected. Slack message returned only to user.')
		logging.debug('Slack message contents: %s',message)
		logging.debug('Outbound message status: %s', r.content)
	else:
		r2 = requests.post(response_channel, data=json.dumps(data), headers=headers) # this sends the response to the user and the specified channel
		logging.info('Slack message sent to channel.')
		logging.debug('Slack message contents: %s',message)
		logging.debug('Outbound message status: %s', r2.content)


if __name__ == '__main__':
	bottle.run(app, host=config.listen_ip, port=config.listen_port)
