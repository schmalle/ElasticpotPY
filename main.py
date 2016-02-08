from bottle import route, run, template, request
import requests
import os.path
import configparser
import base64



#
# read config from eventually existing T-Pot installation (see dtag-dev-sec.github.io)
#
def getConfig():
    if os.path.isfile('/data/ews/conf/ews.cfg'):
        config2 = configparser.ConfigParser()
        config2.read('/data/ews/conf/ews.cfg')
        username = config2.get("EWS", "username")
        token = config2.get("EWS", "token")
        server = config2.get("EWS", "rhost_first")

        return (username, token, server)
    else:
        return (None, None, None)




#
# send the data back home
#
def postdata(url, content, ip):

    username, token, server = getConfig()

    xml = """<EWS-SimpleMessage version="2.0">
    <Authentication>
        <username>tbd</username>
        <token>tbd</token>
    </Authentication>

    <Alert>
        <Analyzer id="4711"/>
        <CreateTime tz="+0200">2015-09-09 16:39:21</CreateTime>
        <Source category="ipv4" port="" protocol="tcp">_IP_</Source>
        <Target category="ipv4" port="80" protocol="tcp">1.2.3.4</Target>
        <Request type="url">_URL_</Request>
        <Request type="raw">_RAW_</Request>
        <Request type="description">ElasticSearch Honeypot : Elasticpot</Request>
    </Alert>
    </EWS-SimpleMessage>"""

    b = bytes(url, 'utf-8')
    out = base64.b64encode(b)

    xml = xml.replace("_IP_", ip)
    xml = xml.replace("_URL_", url)
    xml = xml.replace("_RAW_", out.decode("utf-8") )



    headers = {'Content-Type': 'application/xml'}
    requests.post(server, data=xml, headers=headers)



#@route('/hello/<name>')
#def hello(name):
#    return template('<b>Hello {{name}}</b>!', name=name)

@route('/')
def index():

    txt = open("./templates/index.txt")
    indexData = txt.read()

    return indexData


@route('/_search', method='POST')
def handleSearchExploit():

    postContent = ""
    ip = request.environ.get('REMOTE_ADDR')

    for l in request.body:
        postContent += l.decode("utf-8")



    postdata(request.url, request.url + "Body: " + postContent, ip)
    return "Found attack: " + request.url + postContent


run(host='localhost', port=9404)