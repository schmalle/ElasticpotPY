from bottle import route, run, template
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
    xml = """my xml"""
    headers = {'Content-Type': 'application/xml'}
    requests.post('http://www.my-website.net/xml', data=xml, headers=headers)



@route('/hello/<name>')
def hello(name):
    return template('<b>Hello {{name}}</b>!', name=name)

@route('/')
def index(name):
    return template('<b>Hello {{name}}</b>!', name=name)


@route('/_search')
def index(name):
    return template('<b>Hello {{name}}</b>!', name=name)

run(host='localhost', port=8080)