import logging 
from log import CustomFormatter
import socket

class PeerManager:
    def __init__(self):
        # Handle Logging 
        self.logger = logging.getLogger("Peer Manager")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

        # initiate peers 
        self.peers = dict()
        self.logger.warning("Peer Manager started")


    def remove_service(self, zeroconf, type, name):
        #print("Service %s removed" % (name,))
        self.logger.warning("Peer " + name + " left")
        del self.peers[name]
        self.logger.info("Current peers: " + self.peers.__str__())

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        self.logger.warning("Peer " + name + " joined")
        self.logger.info("Service %s added, service info: %s" % (name, info))
        self.peers[name] = socket.inet_ntoa(info.addresses[0]) + ":" + str(info.port)
        self.logger.info("Current peers: " + self.peers.__str__())

    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        self.logger.warning("Peer " + name + " upated")
        self.logger.info("Service %s updated, service info: %s" % (name, info))
        self.peers[name] = socket.inet_ntoa(info.addresses[0]) + ":" + str(info.port)
        self.logger.info("Current peers: " + list(self.peers).__str__())
