from bottle import route, run, template, request
import requests
import os.path
from simpleconfigparser import simpleconfigparser



#
# read config from eventually existing T-Pot installation (see dtag-dev-sec.github.io)
#
def getConfig():
    if os.path.isfile('/data/ews/conf/ews.cfg'):
        config = simpleconfigparser()
        config.read('/data/ews/conf/ews.cfg')
        username = config(['EWS']['username'])
        token = config(['EWS']['rhost_first'])
        server = config(['EWS']['token'])
        return (username, token, server)
    else:
        return (None, None, None)






#
# send the data back home
#
def postdata(xmldata):
    xml = """<EWS-SimpleMessage version="2.0">
    <Authentication>
        <username>tbd</username>
        <token>tbd</token>
    </Authentication>

    <Alert>
        <Analyzer id="4711"/>
        <CreateTime tz="+0200">2015-09-09 16:39:21</CreateTime>
        <Source category="ipv4" port="" protocol="tcp">1111</Source>
        <Target category="ipv4" port="80" protocol="tcp">1.2.3.4</Target>
        <Request type="url">/cgi-bin/.br/style.css</Request>
        <Request type="raw">R0VUIC9jZ2ktYmluLy5ici9zdHlsZS5jc3MgSFRUUC8xLjENCkFjY2VwdDogdGV4dC9jc3MsKi8q
            O3E9MC4xLCovKg0KQWNjZXB0LUVuY29kaW5nOiBnemlwLGRlZmxhdGUNCkNvbm5lY3Rpb246IEtl
            ZXAtYWxpdmUNCkZyb206IGdvb2dsZWJvdChhdClnb29nbGVib3QuY29tDQpIb3N0OiB3d3cud2Vi
            bWFpbGhvdXNlLmRlDQpSZWZlcmVyOiBodHRwOi8vd3d3LndlYm1haWxob3VzZS5kZS9jZ2ktYmlu
            Ly5ici9wYXRoLnBocA0KVXNlci1BZ2VudDogTW96aWxsYS81LjAgKGNvbXBhdGlibGU7IEdvb2ds
            ZWJvdC8yLjE7ICtodHRwOi8vd3d3Lmdvb2dsZS5jb20vYm90Lmh0bWwp
        </Request>
        <Request type="description">WebHoneypot : Glastopf v3.1</Request>
        <AdditionalData meaning="host" type="string">www.webe.de</AdditionalData>
        <AdditionalData meaning="sqliteid" type="integer">3688</AdditionalData>
    </Alert>
</EWS-SimpleMessage>"""




    headers = {'Content-Type': 'application/xml'}
    requests.post('http://127.0.0.1:8080/reportalarm', data=xml, headers=headers)



@route('/hello/<name>')
def hello(name):
    return template('<b>Hello {{name}}</b>!', name=name)

@route('/')
def index(name):
    return template('<b>Hello {{name}}</b>!', name=name)


@route('/_search', method='POST')
def handleSearchExploit():

    postContent = ""

    for l in request.body:
        postContent += l.decode("utf-8")


    postdata("")
    return "Found attack: " + request.url + postContent


run(host='localhost', port=9300)