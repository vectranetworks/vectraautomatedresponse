# Address group to which to add internal IPs for blocking (E-W traffic).
INTERNAL_ADDRESS_GROUP = "Internal-Block"
# Address group to which to add external IPs for blocking (N-S traffic).
EXTERNAL_ADDRESS_GROUP = "External-Block"
# Create and populate a dict for each Firewall instance
IP = "10.203.1.68"
PORT = 443
TOKEN = "youneedanapitoken"
VDOM = "root"
VERIFY = False

# STOP
FIREWALLS = [{"IP": IP, "PORT": PORT, "TOKEN": TOKEN, "VDOM": VDOM, "VERIFY": VERIFY}]
