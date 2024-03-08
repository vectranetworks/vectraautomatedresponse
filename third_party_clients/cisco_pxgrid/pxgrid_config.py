PXGRID_APPLIANCE_LIST = [""]  # list of fqdn or ip of pxgrid
PXGRID_PORT = 8910
# path to cert.pem
PXGRID_CERT = ""  # path to the cert
# path to key
PXGRID_KEY = ""  # path to the key
# path to server cert
PXGRID_CA_BUNDLE = ""  # Create the CA bundle from the ISE zip file
PXGRID_VERIFY = "False"  # "True" or "False"

# We need first to put the endpoint in a temporary policy to make the port bounce
QUARANTAINE_POLICY = "block"
