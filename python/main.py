
from net_proxy import CapsuleNetProxy

c = CapsuleNetProxy()

try:
    while(True):
        s = input("Enter your RIB query: ")
        c.query(s)
finally:
    pass