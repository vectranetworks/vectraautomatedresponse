# Cisco pxGrid Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cisco pxGrid API.  

# Requirements
- __Python packages__
  - requests
  - xmltodict

# Configuration
This client uses the configuration file [pxgrid_config.py](pxgrid_config.py). 
  - `APPLIANCE_LIST`: list containing FQDN/IP of pxGrid appliances
  - `PORT`: pxGrid port (default: 8910)
  - If using certificate authentication:
    - `CERT`: path to pxGrid certificate; created in Cisco ISE GUI
    - `KEY`: path to pxGrid private key;  created in Cisco ISE GUI
    - `CA_BUNDLE`: path to pxGrid CA bundle; created in Cisco ISE GUI
      - __Note:__ This is created by combining all of the ISE CA certificates from the ISE zip file
  - `CHECK_SSL`: set to True to verify server SSL certificate (default: False)

# Example Config
```
APPLIANCE_LIST = [""]  # list of fqdn or ip of pxgrid
PORT = 8910
CERT = ""  # path to the cert
KEY = ""  # path to the key
CA_BUNDLE = ""  # Create the CA bundle from the ISE zip file
CHECK_SSL = "False"  # "True" or "False"
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Cisco ISE username and password with the following permissions:
  - __NOTE:__ The account associated with the credentials must be authorized within Cisco ISE

# Cisco ISE: Enable API Service
- In the Cisco ISE GUI, click the Menu icon and choose Administration > System > Settings > API Settings > API Service Settings.
- In the API Service Settings for Primary Administration Node area, click the ERS (Read/Write) toggle button to enable ERS on the Primary Administration node (PAN)
- In the API Service Settings for All Other Nodes area, click the ERS (Read) toggle button to enable the ERS on all other nodes
- In the CSRF Check area, click the radio button for one of the following options:
  - Use CSRF Check for Enhanced Security
  - Disable CSRF for ERS Request

# Enablement
To utilize this client within the VAR Framework, add `"cisco_pxgrid"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API 2.0

# Resources
- https://developer.cisco.com/docs/pxgrid/learning-pxgrid/