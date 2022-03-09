
import zmq
import time
from threading import Thread
import logging 

PROXY_PORT = 5555


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class RIB(): 
    def __init__(self):
        # Handle Logging 
        self.logger = logging.getLogger("Routing_Information_Base")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

        self.rib = dict()
        self.logger.warning("RIB started with empty cache")
    
    def query(self, name):
        if name in self.rib:
            return self.rib[name]
        else:
            return False

    def handle_advertisement(self, name, advertise_pdu):
        self.rib[name] = advertise_pdu
        self.logger.warning("Capsule name " + name + " has been added to the RIB")

    def dump_rib(self):
         self.logger.debug(self.rib.__str__())
        
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
        self.logger.info("Current peers: " + self.peers.__str__())

from zeroconf import IPVersion, ServiceInfo, Zeroconf, ServiceBrowser
import socket
import random


class CapsuleNetProxy():
    def __init__(self):

        # Handle Logging 
        self.logger = logging.getLogger("Capsule_Network_Proxy")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

        # Handle RIB 
        self.rib = RIB()


        # Handle Proxy
        if not self.check_open_port(PROXY_PORT):
            self.m_unqiue_port = PROXY_PORT
        else:
            self.m_unqiue_port = random.randint(5005, 10000)
        
        self.m_unqiue_name = str(self.m_unqiue_port)
        info = ServiceInfo(
            "_capsule._udp.local.",
            f"{self.m_unqiue_name}._capsule._udp.local.",
            addresses=[socket.inet_aton("127.0.0.1")],
            port=self.m_unqiue_port,
            #properties={'path': '/~paulsm/'},
            server="ash-2.local."
        )
        self.zeroconf = Zeroconf()
        self.zeroconf.register_service(info)
        self.peer_management = PeerManager()
        self.browser = ServiceBrowser(self.zeroconf, "_capsule._udp.local.", self.peer_management)
                

        # start recv network thread
        thread = Thread(target = self.receive, args = ())
        thread.start()

    def send(self, address, message):
        # get send context
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect (f"tcp://" + address)
        self.socket.send (message)

    def broadcast(self, message):
        peers = self.peer_management.peers.values()
        self.logger.debug("The current peer list: " + peers.__str__())
        for peer in peers:
            self.send(peer, message)

        
    def receive(self):
        self.logger.warning("Network Proxy Receiving Thread started")
        # Socket to talk to server
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind (f"tcp://*:{self.m_unqiue_port}")
        while True:
            message = socket.recv()
            print("received new message")
            splitted = message.split(b",,,")
            packet_type = splitted[0]
            if(packet_type == b"ADV"):
                hash = splitted[-1]
                # already in RIB, don't process the advertisement
                if self.rib.query(hash.hex()):
                    self.logger.warning("Advertisement " + hash.hex() + " in RIB, don't process")
                    continue
                self.logger.debug(b"Advertisement: " + message[:100] + b"......" + message[-100:])
                self.logger.debug(b"Received Advertisement Hash: " + hash)
                self.logger.warning("Received Advertisement in Hex: " + hash.hex())
                pub_key = splitted[-2]
                self.logger.debug(b"Received Pub Key: " + pub_key)
                self.rib.handle_advertisement(hash.hex(), message)
                self.logger.warning("Broadcast "+ hash.hex() + " advertisement to other peers")
                self.broadcast(message)


    def check_open_port(self, port_num):
        ret = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1',port_num))
        if result == 0:
            self.logger.debug(f"port {port_num} open")
            ret =  True 
        else:
            self.logger.debug(f"port {port_num} not open")
            ret =  False
        sock.close()
        return ret 






c = CapsuleNetProxy()

try:
    input()
finally:
    c.zeroconf.close()