from bottle import route, run, request, error
import requests
import os.path
import configparser
import base64
import datetime
import ipaddress
import urllib.request
from urllib.parse import quote
import json
import re

##########################
# Config section
##########################

configfile = "elasticpot.cfg"   # point to elasticpot.cfg or an ews.cfg if you use ewsposter
hostport = 9200                 # port to run elasticpot on

##########################
# FUNCTIONS
##########################

# read config from eventually existing T-Pot installation (see dtag-dev-sec.github.io)
def getConfig():
        config2 = configparser.ConfigParser()
        config2.read(configfile)
        username = config2.get("EWS", "username")
        token = config2.get("EWS", "token")
        server = config2.get("EWS", "rhost_first")
        nodeid = config2.get("ELASTICPOT", "nodeid")
        ewssender = config2.get("ELASTICPOT", "elasticpot")
        jsonpath = config2.get("ELASTICPOT", "logfile")
        ignorecert = config2.get("EWS", "ignorecert")
        hostip = config2.get("MAIN", "ip")

        return (username, token, server, nodeid, ignorecert, ewssender, jsonpath, hostip)

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
    global username, token, server, nodeid, ignorecert, ewssender, jsonpath, hostip

    curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%S')
    data = {}
    data['timestamp'] = curDate
    data['event_type'] = "alert"
    data['src_ip'] = ip
    data['src_port'] = srcport
#    data['dest_ip'] = hostip
    urlparts = request.environ.get('bottle.request.urlparts')
    pattern = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)")    
    destip = str(pattern.search(str(urlparts)).group())
    if destip == None :
        data['dest_ip'] = hostip
    else:
        data['dest_ip'] = destip
    data['dest_port'] = hostport
    data2 = {}
    data2['name'] = "Elasticpot"
    data2['nodeid'] = nodeid
    data2['name'] = "Elasticpot"
    data2['query'] = querystring
    data2['postdata'] = postdata
    data2['raw'] = raw
    data['honeypot'] = data2

    # Send to json logfile
    if os.path.isfile(configfile) and ewssender.upper() == "TRUE":
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

        try:
            requests.post(server, data=xml, headers=headers, verify=ignorecert, timeout=5)
        except requests.exceptions.Timeout:
            print("Elasticpot: Error trying to submit attack: Connection timeout.")
        except requests.exceptions.RequestException as e:
            print(e)


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
    print("Elasticpot: Access to non existing ressource: " + request.url + " " + postContent)
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
    print ("Elasticpot: Found possible attack (/_cat/indices): " + request.url)
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
    print ("Elasticpot: Found possible attack (_search): " + request.url)
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
    print("Elasticpot: Found possible attack (_search): " + request.url + postContent)
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
    print("Elasticpot: Access to ElasticSearch head plugin: " + request.url + " " + postContent)
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

# initialize relevant data from the config file
if (not os.path.isfile(configfile)):
    print("Elasticpot: Failed to read configfile. Elasticpot will exit.")
    exit(1)
else: 
    username, token, server, nodeid, ignorecert, ewssender, jsonpath, hostip = getConfig()
    try:
        if ((ipaddress.ip_address(hostip).is_private) and not (ipaddress.ip_address(hostip).is_global)):
            if (ipaddress.ip_address(hostip).is_private):
                try:
                    # if IP is private, determine external ip via lookup
                    hostip = requests.get('https://api.ipify.org', timeout=5).text
                    print("Elasticpot: IP in config file is private. Determined the public IP %s" % hostip)
                except:
                    print("could not determine external IP address")
    except:
        print("IP is invalid in config file, please make sure to put a valid IP address in config file: " + hostip)
        exit(1)

    srcport = 44927 # Cannot be retrieved via bottles request api, this is just a dummy port
# done Initialization

# run server
run(host='0.0.0.0', port=hostport)
