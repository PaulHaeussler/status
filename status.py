import datetime
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import urllib
import re
import requests


from os.path import dirname, abspath
from flask import Flask, request, make_response, render_template, jsonify
from loguru import logger
from requests import get
from mcstatus import JavaServer

from db import MySQLPool

force_mobile = False
wait_time = 60
rcon_pw = "ovTV2NCq"

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logger.add("latest.log")


def read_args():
    import argparse
    parser = argparse.ArgumentParser(
        description='Availability checker')
    parser.add_argument('dbhost')
    parser.add_argument('dbschema')
    parser.add_argument('dbuser')
    parser.add_argument('dbpw')
    args = vars(parser.parse_args())
    return args


def is_port_in_use(host: str, port: int) -> bool:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0



def fetch_minecraft_metadata(host, port):
    server = JavaServer.lookup(f"{host}:{port}")

    # Query the server
    status = server.status()
    query = server.query()

    # Print server details
    print(f"Server Software: Assuming Fabric (since exact info isn't provided directly)")
    print(f"Version: {status.version.name}")
    print(f"Players Online: {status.players.online}")
    print(f"Max Players: {status.players.max}")
    print(f"Player Names: {query.players.names}")



class Status:

    def __init__(self):
        logger.info("Fetching Config...")
        self.json_file = dirname(abspath(__file__)) + "/config.json"
        self.config = json.load(open(self.json_file))
        self.data = {
            "lastChecked": datetime.datetime.utcfromtimestamp(0),
            "nextCheck": datetime.datetime.now(),
            "services": self.config["services"]
        }

        try:
            args = read_args()
            dbhost = args['dbhost']
            dbuser = args['dbuser']
            dbpw = args['dbpw']
            dbschema = args['dbschema']


            self.db = MySQLPool(host=dbhost, user=dbuser, password=dbpw, database=dbschema,
                        pool_size=15)
        except:
            logger.warning("No DB params supplied!")


        self.validate_ips()


    def isMobile(self, request):
        ua = request.headers.get('User-Agent')
        if ua is None:
            ua = ""
        ua = ua.lower()
        if force_mobile:
            ua += "android"
        return "iphone" in ua or "android" in ua

    def validate_ips(self):
        # find own ip
        ip = get('https://api.ipify.org').content.decode('utf8')
        # compare which domain resolves to my ip
        dns_matches = False
        for _, host in enumerate(self.config["instances"]):
            dns = socket.getaddrinfo(host["domain"], 80)
            if dns[0][4][0] == ip:
                dns_matches = True
                if host["ip"] != ip:
                    logger.warning(f"Old IP {host['ip']} for domain {host['domain']} is invalid, using new {ip}")
                    self.config["instances"][_]["ip"] = ip
                    self.config["hosts"][host["name"]] = ip
                    if host["name"] == "Seiyoku":
                        self.config["hosts"]["Tower"] = ip
                    self.rewriteConfig(self.config)
                    self.update_config()
            print()


    def get_ip(self, req):
        ip = ""
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            ip = (request.environ['REMOTE_ADDR'])
        else:
            ip = (request.environ['HTTP_X_FORWARDED_FOR'])  # if behind a proxy
        return ip


    def update_config(self):
        # TODO der müll hier wird nicht so worken, das muss die jeweils andere IP sein. Wg. dem nginx klappt das nicht, also geh ich entweder direkt auf port und schalt den frei, oder der code nimmt die jeweils andere domain und die haben in dns A, B und B, A
        try:
            requests.post('https://status.seiyoku.me/updateConfig', json=self.config)
        except:
            logger.error("Failed to share updated config!")



    def rewriteConfig(self, new_config):
        with open(self.json_file, 'w') as filetowrite:
            filetowrite.write(json.dumps(new_config))


    def dispatch_thread(self):
        self.checkThread = threading.Thread(target=self.check_availability, args=())
        self.checkThread.start()

    def get_domain(self, service):
        if "domain" in service:
            return service["domain"]
        elif "host" in service:
            for inst in self.config["instances"]:
                if inst["name"] == service["host"]:
                    return inst["domain"]
            logger.error(f"host {service['host']} not found")
        else:
            logger.error("host unknown")

    def check_availability(self):
        while True:
            logger.info("Check Thread active, checking now...")

            for _, service in enumerate(self.data["services"]):
                logger.info(f"Checking service {service['name']}...")
                try:
                    isAvailable = False
                    version = ""
                    response_time = 0
                    if "rcon_port" in service:
                        #rcon
                        current_players = 0
                        max_players = 0

                        fetch_minecraft_metadata(self.get_domain(service), service["port"])


                    elif service["type"] in ["Webserver", "Video Streaming"]:
                        #http
                        start_time = time.time_ns()
                        isAvailable, version = self.check_webserver(service, _)
                        if not isAvailable:
                            start_time = time.time_ns()
                            isAvailable, version = self.check_webserver(service, _, "http://")
                            if isAvailable:
                                self.data["services"][_]["info"] = self.data["services"][_].get("info", "") + "http only;"
                        response_time = (time.time_ns() - start_time)/1000000
                    else:
                        #ping
                        start_time = time.time_ns()
                        isAvailable = is_port_in_use(self.get_domain(service), service["port"])
                        response_time = (time.time_ns() - start_time) / 1000000
                        self.data["services"][_]["info"] = self.data["services"][_].get("info", "") + "ping only;"

                except:
                    logger.error(f"Failed to check service {service['name']}!")

                if isAvailable:
                    self.data["services"][_]["status"] = "online"
                else:
                    self.data["services"][_]["status"] = "offline"

                self.data["services"][_]["response_time"] = response_time
                self.data["services"][_]["version"] = version
                logger.info(f"service {service['name']} checked!")
            self.data["lastChecked"] = datetime.datetime.now()
            self.data["nextCheck"] = datetime.datetime.now() + datetime.timedelta(0, wait_time)
            time.sleep(wait_time)



    def check_webserver(self, service, _, protocol="https://"):
        isAvailable = False
        version = ""
        try:
            response = requests.get(protocol + self.get_domain(service) + ":" + str(service["port"]), timeout=10)
            self.data["services"][_]["response_code"] = response.status_code
            version = response.headers.get("server", "")
            if response.status_code in [200, 201]:
                isAvailable = True
            else:
                isAvailable = False
        except requests.exceptions.Timeout:
            isAvailable = False
        except (ssl.SSLCertVerificationError, requests.exceptions.SSLError) as e:
            isAvailable = False
            self.data["services"][_]["info"] = "cert invalid; "


        return isAvailable, version

    @logger.catch
    def create_app(self):

        self.app = Flask(__name__)


        @self.app.route('/', methods=['GET', 'POST'])
        def index():
            return render_template("index.html")


        @self.app.route('/data', methods=['GET'])
        def data():
            return jsonify(self.data)


        @self.app.route('/updateConfig', methods=['POST'])
        def updateConfig():
            new_config = request.get_json()
            print()
            #validate sender
            authorized_ips = ["127.0.0.1"]
            for host in self.config['instances']:
                authorized_ips.append(host['ip'])

            res = make_response()
            if self.get_ip(request) in authorized_ips:
                logger.info(f"Config update received from {self.get_ip(request)}, updating config...")
                self.rewriteConfig(new_config)
                self.config = new_config
                res.status_code = 200
                return res
            else:
                logger.warning(f"Unauthorized config update from IP {self.get_ip(request)}")
                res.status_code = 401
                return res



        logger.info("Dispatching check thread...")
        self.dispatch_thread()
        logger.info("Webserver ready!")
        if __name__ == '__main__':
            self.app.run(host='0.0.0.0', port=22500)
        else:
            return self.app


s = Status()
s.create_app()
