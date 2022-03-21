#!/usr/bin/python3
import zmq
import time
from threading import Thread
from log import CustomFormatter
from rib import RIB
from peer_manager import PeerManager
from enclave import Enclave

import logging 
PROXY_PORT = 5555
LOCAL_NET_ENCLAVE_PORT = 5006

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
        self.rib_cache = RIB()

        self.enclave_attached = None

        # Handle Proxy
        if not self.check_open_port(PROXY_PORT):
            self.m_unqiue_port = PROXY_PORT
        else:
            self.m_unqiue_port = random.randint(5005, 10000)
        self.m_addr = "localhost:" + str(self.m_unqiue_port)
        
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
            if peer != self.m_addr:
                self.send(peer, message)

    def query(self, query_name):
        self.logger.debug("Querying name " + query_name)
        if query_name in self.rib_cache.rib and False: 
            self.logger.debug("Name is in RIB cache")
        else:
            self.logger.debug("Name is not in RIB cache, query ")
            message = ("QUERY,,," + query_name).encode()
            self.enclave_attached.send(message)
            
    def receive(self):
        self.logger.warning("Network Proxy Receiving Thread started")
        # Socket to talk to server
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind (f"tcp://*:{self.m_unqiue_port}")
        while True:
            message = socket.recv()
            splitted = message.split(b",,,")
            packet_type = splitted[0]
            if(packet_type == b"ADV"):
                hash = splitted[-1]
                # already in RIB, don't process the advertisement
                if self.rib_cache.query(hash.hex()):
                    self.logger.warning("Advertisement " + hash.hex() + " in RIB, don't process")
                    continue
                self.logger.debug(b"Advertisement: " + message[:100] + b"......" + message[-100:])
                self.logger.debug(b"Received Advertisement Hash: " + hash)
                self.logger.warning("Received Advertisement in Hex: " + hash.hex('0', 2))
                pub_key = splitted[-2]
                self.logger.debug(b"Received Pub Key: " + pub_key)
                self.rib_cache.handle_advertisement(hash.hex(), message)
                self.logger.warning("Broadcast "+ hash.hex() + " advertisement to other peers")
                self.broadcast(message)

                #check and update RIB 
                if not self.enclave_attached:
                    self.check_enclave_attached()
                self.logger.debug(b"send message to enclave: " + message)
                self.enclave_attached.send(message)

    def check_enclave_attached(self):
        if self.check_open_port(LOCAL_NET_ENCLAVE_PORT):
            self.enclave_attached = Enclave(LOCAL_NET_ENCLAVE_PORT)

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




