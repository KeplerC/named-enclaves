
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

class Capsule_Net_Proxy():
    def __init__(self):
        self._publishers = {}
        self._subscribers = {}
        

        # Handle Logging 
        self.logger = logging.getLogger("Capsule Network Proxy")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

        # get send context
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)

        # start recv network thread
        thread = Thread(target = self.receive, args = ())
        thread.start()

    def send(self, message):
        self.socket.connect (f"tcp://localhost:{PROXY_PORT}")
        print ("Send: " + message)
        self.socket.send (("%s %s" % ("", message)).encode('utf-8'))

        
    def receive(self):
        self.logger.debug("Network Proxy Receiving Thread started")
        # Socket to talk to server
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind (f"tcp://*:{PROXY_PORT}")
        while True:
            message = socket.recv()
            
            splitted = message.split(b",,,")
            packet_type = splitted[0]
            if(packet_type == b"ADV"):
                self.logger.debug(b"Advertisement: " + message[:100] + b"......" + message[-100:])
                hash = splitted[-1]
                self.logger.debug(b"Received Advertisement Hash: " + hash)
                self.logger.warning("Received Advertisement in Hex: " + hash.hex())
                pub_key = splitted[-2]
                self.logger.debug(b"Received Pub Key: " + pub_key)
                


c = Capsule_Net_Proxy()
time.sleep(1000)