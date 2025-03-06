# Meraki Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Meraki API.  

# Requirements
- __Python packages__
  - requests


# Configuration
This client uses the configuration file [meraki_config.py](meraki_config.py). 
  - `MERAKI_URL`: hostname of the bitdefender server.
  - `BLOCK_GROUP_POLICY`:
  - `PORT_SCHEDULE`:
  - `BLOCK_MULTIPLE_MAC`:
  - `BLOCK_MULTIPLE_IP`:
  - `BLOCK_INACTIVE_CLIENTS`:
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)

# Example Config
```
MERAKI_URL = "https://api.meraki.com/api/v1"
BLOCK_GROUP_POLICY = ""
PORT_SCHEDULE = "Block"
BLOCK_MULTIPLE_MAC = True
BLOCK_MULTIPLE_IP = False
BLOCK_INACTIVE_CLIENTS = True
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Meraki API Key 

# Enablement
To utilize this client within the VAR Framework, add `"meraki"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__

# Resources
- https://developer.cisco.com/meraki/api-v1/introduction/
