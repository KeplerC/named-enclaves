
import zmq
import time
from threading import Thread

PROXY_PORT = 5555

class GDP_Client():
    def __init__(self):
        self._publishers = {}
        self._subscribers = {}
        
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        #  Get the reply.
        thread = Thread(target = self.receive, args = ())
        thread.start()


    def send(self, message):
        self.socket.connect (f"tcp://localhost:{PROXY_PORT}")
        print ("Send: " + message)
        self.socket.send (("%s %s" % ("", message)).encode('utf-8'))

        
    def receive(self):
        print("Network Thread started")
        # Socket to talk to server
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind (f"tcp://*:{PROXY_PORT}")
        while True:
            message = socket.recv().decode()
            print("Received message: ", message)
            # data = json.loads(message)


c = GDP_Client()
c.send("hello")
time.sleep(1000)