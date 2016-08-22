#!/usr/bin/env python

################################################################################
#
# A poorly written Slack integration that enables querying Virustotal
# directly from Slack
# 
# https://github.com/ecapuano/slackbot
#
################################################################################

import bottle 
import urllib
import urllib2
import argparse
import hashlib
import re
import requests
import json
import socket
import config
import sys
import logging

debug = "no" # set to 'yes' to print messages to console

logging.basicConfig(filename='virustotal.log',format='%(asctime)s %(message)s',level=logging.INFO)
logging.info('Server started.')

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
    vtarg = bottle.request.forms.get('text')
    trigger_words = bottle.request.forms.get('trigger_words')
    response_url = bottle.request.forms.get('response_url')

    if token != config.slack_token:  # integration token
        print "INVALID REQUEST RECEIVED! --> %s" % body
        logging.warning('Invalid Request Received %s', body)
        return "LOL NOPE"

    logging.debug('Incoming request: %s', body)

    logging.info('VT request received from user: %s - resource: %s', user_name, vtarg)

    if ("http" in vtarg) or ("www" in vtarg) or (".com" in vtarg):
        if debug == "yes":
            print "URL Detected"
        logging.info('URL Detected')
        vt.urlScan(vtarg,user_name,response_url)
    elif re.findall(r"([a-fA-F\d]{32})", vtarg):
        if debug == "yes":
            print "MD5 detected"
        logging.info('MD5 Detected')
        vt.getReport(vtarg,user_name,response_url)
    else:
        if debug == "yes":
            print "Not URL or MD5"
        message = "You did not provide a valid URL or MD5 hash.\nPlease try again in the format `/virustotal http://malware.ru` or `/virustotal 99017f6eebbac24f351415dd410d522d`"
        logging.warning('Invalid query passed by user: %s -- %s', user_name, vtarg)
        status = "fail"
        sendToSlack(message,response_url,status)

class vtAPI():
    def __init__(self):
        self.api = config.vt_api
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def getReport(self,md5,user_name,response_url):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        parse(jdata,user_name,response_url)

    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"

    def urlScan(self,vtarg,user_name,response_url):
        param = {'resource':vtarg,'apikey':self.api}
        url = self.base + "url/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata = json.loads(result.read())
        urlparse(jdata,user_name,response_url)


################### Not in use yet
def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else:
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest()
####################


def parse(jdata,user_name,response_url):
  if jdata['response_code'] == 0:
    message = "That Hash Not Found in VT"
    logging.warning('Hash not found in VT')
    status = "fail"
    sendToSlack(message,response_url,status)
    return 0

  positives = str(jdata['positives'])
  total = str(jdata['total'])
  md5 = str(jdata['md5'])
  message = "Results for File: \t" + md5 + "\n"
  message += "Detected Malicious by: \t" + positives + "/" + total + "\n"
  if 'Sophos' in jdata['scans']:
    Sophos = "Sophos: \t" + jdata.get('scans', {}).get('Sophos').get('result') + "\n"
    message += Sophos
  if 'Kaspersky' in jdata['scans']:
    Kaspersky = "Kaspersky: \t" + jdata.get('scans', {}).get('Kaspersky').get('result') + "\n"
    message += Kaspersky
  if 'ESET-NOD32' in jdata['scans']:
    ESET = "ESET: \t" + jdata.get('scans', {}).get('ESET-NOD32').get('result') + "\n"
    message += ESET
  if 'AegisLab' in jdata['scans']:
    Aegis = "AegisLab: \t" + jdata.get('scans', {}).get('AegisLab').get('result') + "\n"
    message += Sophos

  message += 'Scanned on: \t' + jdata['scan_date'] + "\n"
  message += jdata['permalink'] + "\n"
  if debug == "yes":
      print message
  status = "pass"
  sendToSlack(message,response_url,status)


def urlparse(jdata,user_name,response_url):
  if jdata['response_code'] == 0:
    message = "That Site Not Found in VT"
    logging.warning('Site not found in VT')
    status = "fail"
    sendToSlack(message,response_url,status)
    if debug == "yes":
        print "Request from " + user_name + " not found in VT database."
    return 0
  positives = str(jdata['positives'])
  total = str(jdata['total'])
  url = jdata['url']
  message = "Results for Site: \t" + url + "\n"
  message += "Determined Malicious by: \t" + positives + "/" + total + "\n"
  logging.info('Determined Malicious by: %s / %s', positives, total)
  if 'OpenPhish' in jdata['scans']:
    openphish = "OpenPhish: \t" + jdata.get('scans', {}).get('OpenPhish').get('result') + "\n"
    message += openphish
  if 'PhishLabs' in jdata['scans']:
    phishlabs = "PhishLabs: \t" + jdata.get('scans', {}).get('PhishLabs').get('result') + "\n"
    message += phishlabs
  if 'Sophos' in jdata['scans']:
    Sophos = "Sophos: \t" + jdata.get('scans', {}).get('Sophos').get('result') + "\n"
    message += Sophos
  if 'BitDefender' in jdata['scans']:
    BitDefender = "BitDefender: \t" + jdata.get('scans', {}).get('BitDefender').get('result') + "\n"
    message += BitDefender
  if 'Google Safebrowsing' in jdata['scans']:
    googlesafe = "Google: \t" + jdata.get('scans', {}).get('Google Safebrowsing').get('result') + "\n"
    message += googlesafe
  if 'Avira' in jdata['scans']:
    Avira = "Avira: \t" + jdata.get('scans', {}).get('Avira').get('result') + "\n"
    message += Avira

  message += 'Scanned on: \t' + jdata['scan_date'] + "\n"
  message += jdata['permalink'] + "\n"
  if debug == "yes":
      print message
  status = "pass"
  sendToSlack(message,response_url,status)


def sendToSlack(message,response_url,status):
    url = response_url
    slack_url = config.slack_url
    data = {"username": 'VirusTotal', "text": message}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    # this sends the response to the user privately
    r = requests.post(url, data=json.dumps(data), headers=headers)
    logging.info('Message returned to user')

    # following only occurs if the query was a success and posts results publicly in a specified channel
    if status == "pass":
        r2 = requests.post(slack_url, data=json.dumps(data), headers=headers)
        logging.info('Message sent to slack channel')
    logging.debug('Outbound message status: %s', r.content)

if __name__ == '__main__':
    vt = vtAPI()
    bottle.run(app, host=config.listen_ip, port=config.listen_port)
