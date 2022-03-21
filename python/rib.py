

import logging 
from log import CustomFormatter

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
        self.dump_rib()

    def dump_rib(self):
         self.logger.debug("Current RIB contains: " + self.rib.keys().__str__())
        