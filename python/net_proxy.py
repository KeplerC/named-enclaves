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

import socket
import random
import asyncio
from kademlia.network import Server

SERVER_ADDR = "128.32.37.74"
SERVER_PORT = 8468




async def put_key_value(boot_strap_server, key, value):
    # Create a node and start listening on port 5678
    node = Server()
    await node.listen(5678)
    await node.bootstrap([(boot_strap_server, SERVER_PORT)])
    #await node.listen(SERVER_PORT)

   # await node.bootstrap([(boot_strap_server, SERVER_PORT)])

    # set a value for the key "my-key" on the network
    await node.set(key, value)

async def get_key_value(boot_strap_server, key):
    # Create a node and start listening on port 5678
    #await node.listen(SERVER_PORT)
    node = Server()
    await node.listen(8765)
    await node.bootstrap([(boot_strap_server, SERVER_PORT)])
    #await node.bootstrap([(boot_strap_server, SERVER_PORT)])

    # get the value associated with "my-key" from the network
    return await node.get(key)



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
        self.peer_management = PeerManager()

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
        #asyncio.run(get_key_value(SERVER_ADDR, query_name))
        if query_name in self.rib_cache.rib: 
            self.logger.debug("Name is in RIB cache")
        else:
            self.logger.debug("Name is not in RIB cache, query ")
            message = ("QUERY,,," + query_name).encode()
            self.enclave_attached.send(message)
            
    def receive(self):
        global LOCAL_NET_ENCLAVE_PORT
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
                hash = splitted[-2]
                # already in RIB, don't process the advertisement
                if self.rib_cache.query(hash.hex()):
                    self.logger.warning("Advertisement " + hash.hex() + " in RIB, don't process")
                    continue
                self.logger.debug(b"Advertisement: " + message[:100] + b"......" + message[-100:])
                self.logger.debug(b"Received Advertisement Hash: " + hash)
                self.logger.warning("Received Advertisement in Hex: " + hash.hex())
                pub_key = splitted[-3]
                self.logger.debug(b"Received Pub Key: " + pub_key)

                from_addr = splitted[-1].decode()
                self.rib_cache.handle_advertisement(hash.hex(), message, from_addr)
                #self.logger.warning("Broadcast "+ hash.hex() + " advertisement to other peers")
                #self.broadcast(message)

                #check and update RIB 
                if not self.enclave_attached:
                    LOCAL_NET_ENCLAVE_PORT = int(from_addr.split(":")[-1])
                    self.logger.warning("Enclave not attached, trying to attach to " + str(LOCAL_NET_ENCLAVE_PORT))
                    self.check_enclave_attached()
                self.logger.warning("Enclave attached with " + str(LOCAL_NET_ENCLAVE_PORT))
                
                self.enclave_attached.send(message)
                self.benchmark() 

                #asyncio.run(put_key_value(SERVER_ADDR,hash.hex(), message))

            if(packet_type == b"DATA"):
                print(splitted)
                receiver = splitted[1].hex() 
                sender = splitted[2].hex() 
                data = splitted[3].decode()
                self.logger.warning("[DATA] Receiver: " +  receiver + " Sender: " + sender + " Data: " + data)

                dst = self.rib_cache.query(receiver)
                self.send(dst, message)


    def check_enclave_attached(self):
        if self.check_open_port(LOCAL_NET_ENCLAVE_PORT):
            self.logger.warning("port open for " + str(LOCAL_NET_ENCLAVE_PORT))
            self.enclave_attached = Enclave(LOCAL_NET_ENCLAVE_PORT)
        else:
            self.logger.warning("port not open for " + str(LOCAL_NET_ENCLAVE_PORT))


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


    def benchmark(self):
        self.benchmark_switch()

    def fake_datagram(self, size = 20):
        return b"DATA,,,xklzjCx,,,dksjfljsld,,," + b"s" * size + b",,,localhost:5030"

    def benchmark_switch(self):
        self.logger.warning("running switch benchmark")
        datagram = self.fake_datagram()
        print(datagram)
        #for i in range(5):
        self.enclave_attached.send(datagram)





