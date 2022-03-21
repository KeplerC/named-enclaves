
import zmq


class Enclave:
    def __init__(self, port = 5006):
        self.port = 5006
    
    def send(self, message):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect (f"tcp://localhost:" + str(self.port))
        self.socket.send (message)
