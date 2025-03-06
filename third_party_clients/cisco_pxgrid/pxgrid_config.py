APPLIANCE_LIST = [""]  # list of fqdn or ip of pxgrid
PORT = 8910
# path to cert.pem
CERT = ""  # path to the cert
# path to key
KEY = ""  # path to the key
# path to server cert
CA_BUNDLE = ""  # Create the CA bundle from the ISE zip file
CHECK_SSL = "False"  # "True" or "False"

# We need first to put the endpoint in a temporary policy to make the port bounce
QUARANTAINE_POLICY = "block"
