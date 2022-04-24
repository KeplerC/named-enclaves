
import zmq


class Enclave:
    def __init__(self, port = 5006):
        self.port = port
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect (f"tcp://localhost:" + str(self.port))
    
    def send(self, message):
        print(b"sent: " + message)
        self.socket.send (message)
