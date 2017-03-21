from bottle import route, run, template, request, error
import requests
import os.path
import configparser
import base64
import datetime
import codecs
import ipaddress
import urllib.request
from urllib.parse import quote
import json

##########################
# Config section
##########################

configfile = "/data/ews/conf/ews.cfg" # point to ews.cfg
hostport = 9200 # port to run elasticpot on


##########################
# FUNCTIONS
##########################

# read config from eventually existing T-Pot installation (see dtag-dev-sec.github.io)
def getConfig():
    if os.path.isfile(configfile):
        config2 = configparser.ConfigParser()
        config2.read(configfile)
        username = config2.get("EWS", "username")
        token = config2.get("EWS", "token")
        server = config2.get("EWS", "rhost_first")
        nodeid = config2.get("ELASTICPOT", "nodeid")
        ewssender = config2.get("ELASTICPOT", "elasticpot")
        jsonpath = config2.get("ELASTICPOT", "logfile")
        ignorecert = config2.get("EWS", "ignorecert")

        return (username, token, server, nodeid, ignorecert, ewssender, jsonpath)
    else:
        print("Failed to read configfile.")
        return (None, None, None, None, None, None, None)

# re-assemble raw http request from request headers, return base64 encoded
def createRaw(request):
    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

    # Get post content
    if request.method == "POST":
        postContent = ""
        for l in request.body:
            postContent += l.decode("utf-8")

	# Generate raw http-request manually
    requestheaders=httpreq + " " + request.environ.get('SERVER_PROTOCOL') + "\n"
    requestheaders+="Host: "+ request.get_header('Host') + "\n"
    requestheaders+="User-Agent: "+ request.get_header('User-Agent') + "\n"
    requestheaders+="Accept: "+ request.get_header('Accept') + "\n"
    requestheaders+="Content-Length: "+ request.get_header('Content-Length') + "\n"
    requestheaders+="Content-Type: "+ request.get_header('Content-Type') + "\n" + "\n"
    if request.method == "POST":
        requestheaders+=postContent+"\n"

    # base64 encode
    requestheaders64=base64.b64encode(requestheaders.encode('UTF-8')).decode('ascii')
    return requestheaders64



# Send data to either logfile (for ewsposter, location from ews.cfg) or directly to ews backend
def logData(querystring, postdata, ip,raw):
    username, token, server, nodeid, ignorecert, ewssender, jsonpath = getConfig()

    # Send to json logfile
    if os.path.isfile(configfile) and ewssender.upper() == "TRUE":
        curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%S')
        data = {}
        data['timestamp'] = curDate
        data['event_type'] = "alert"
        data['src_ip'] = ip
        data['src_port'] = str(srcport)
        data['dest_ip'] = hostip
        data['dest_port'] = str(hostport)
        data2 = {}
        data2['name'] = "Elasticpot"
        data2['nodeid'] = nodeid
        data2['name'] = "Elasticpot"
        data2['query'] = querystring
        data2['postdata'] = postdata
        data2['raw'] = raw
        data['honeypot']=data2
        with open(jsonpath, 'a') as outfile:
            json.dump(data, outfile)
            outfile.write('\n')


    # send via own posting mechanism to defined server
    else:
        if (username == None or token == None):
        	print("No credentials found in config file.")
        	return
        txt = open("./templates/ews.txt")
        xml = txt.read()

        xml = xml.replace("_IP_", ip)
        xml = xml.replace("_TARGET_", hostip)
        xml = xml.replace("_SRCPORT_", str(srcport))
        xml = xml.replace("_DSTPORT_", str(hostport))
        xml = xml.replace("_USERNAME_", username)
        xml = xml.replace("_TOKEN_", token)
        xml = xml.replace("_URL_", quote(str(querystring)))
        xml = xml.replace("_RAW_", raw)
        xml = xml.replace("_DATA_", quote(str(postdata)))
        xml = xml.replace("_NODEID_", nodeid)

        curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')

        xml = xml.replace("_TIME_", curDate)

        headers = {'Content-Type': 'application/xml'}

        # fix ignorecert to verifycert logic

        if (ignorecert == None):
            ignorecert = True
        elif (ignorecert == "true"):
            ignorecert = False
        elif (ignorecert == "false"):
            ignorecert = True

        requests.post(server, data=xml, headers=headers, verify=ignorecert)


##########################
####### SITE HANDLER
##########################

# Handle index site
@route('/', method='GET')
def index():

    txt = open("./templates/index.txt")
    indexData = txt.read()

    # Not an attack
    # Return data, do nothing
    return indexData


# handle irrelevant / error requests
@error(404)
def error404(error):
    txt = open("./templates/404.txt")
    indexData = txt.read()

    # DO WE WANT TO LOG THESE???

	# Log request to console
    postContent = ""
    for l in request.body:
        postContent += l.decode("utf-8")
    print("Access to non existing ressource: " + request.url + " " + postContent)
    ip = request.environ.get('REMOTE_ADDR')

    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

	# Create request headers for raw request
    requestheaders64=createRaw(request)

	# Log the data
    logData(httpreq, postContent, ip, requestheaders64)


    # Return data
    return indexData

# handle favicon
@route('/favicon.ico', method='GET')
def getindeces():
    txt = open("./templates/favicon.ico.txt")
    indexData = txt.read()

    # Not an attack
    # Return default data, do nothing
    return indexData

# handle route to indices
@route('/_cat/indices', method='GET')
def getindeces():
    txt = open("./templates/getindeces.txt")
    indexData = txt.read()

    # Log request to console
    postContent = ""
    print ("Found possible attack (/_cat/indices): " + request.url)
    ip = request.environ.get('REMOTE_ADDR')

    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

    # Create request headers for raw request
    requestheaders64=createRaw(request)

    # Log the data
    logData(httpreq, postContent, ip, requestheaders64)

    # Return data
    return indexData

# handle search route (GET)
@route('/_search', method='GET')
def handleSearchExploitGet():

    # Log request to console
    postContent = ""
    print ("Found possible attack (_search): " + request.url)
    ip = request.environ.get('REMOTE_ADDR')

    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

    # Create request headers for raw request
    requestheaders64=createRaw(request)

	# Log the data
    logData(httpreq, postContent, ip, requestheaders64)

    return ""

# handle search route (POST)
@route('/_search', method='POST')
def handleSearchExploit():

    # Log request to console
    postContent = ""
    for l in request.body:
        postContent += l.decode("utf-8")
    print("Found possible attack (_search): " + request.url + postContent)
    ip = request.environ.get('REMOTE_ADDR')

    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

	# Create request headers for raw request
    requestheaders64=createRaw(request)

	# Log the data
    logData(httpreq, postContent, ip, requestheaders64)

    return ""

# handle head plugin
@route('/_plugin/head')
def pluginhead():
    txt = open("./templates/pluginhead.txt")
    indexData = txt.read()

    # Log request to console
    postContent = ""
    for l in request.body:
        postContent += l.decode("utf-8")
    print("Access to ElasticSearch head plugin: " + request.url + " " + postContent)
    ip = request.environ.get('REMOTE_ADDR')

	# Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

	# Create request headers for raw request
    requestheaders64=createRaw(request)

	# Log the data
    logData(httpreq, postContent, ip, requestheaders64)

    # Return data
    return indexData

### More routes to add...


#@route('/<index:path>?pretty', method='PUT')
#def createindex(index):

##########################
##### MAIN START
##########################

# initialize some data
if os.path.isfile(configfile):
    config2 = configparser.ConfigParser()
    config2.read(configfile)
    hostip = config2.get("MAIN", "ip")
# if IP is private, determine external ip via lookup
if (ipaddress.ip_address(hostip).is_private):
    extip = urllib.request.urlopen("http://showip.net").read().decode('utf-8')
    hostip=extip
srcport = 44927 # Cannot be retrieved via bottles request api, this is just a dummy port
# done Initialization

# run server
run(host='0.0.0.0', port=hostport)
