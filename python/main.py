
from net_proxy import CapsuleNetProxy

c = CapsuleNetProxy()

try:
    input()
finally:
    c.zeroconf.close()