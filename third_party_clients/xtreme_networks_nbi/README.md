# Xtreme Networks Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Xtreme Networks NBI API.

# Requirements
- __Python packages__
  - requests
  - pyVmomi
- __Vectra Integrations__
  - vCenter External Connector 
    - In the UI -> Settings -> External Connectors -> vCenter
    - ___Note:___ This client utilizes the vCenter UUID Host ID artifact as the key to isolate/unisolate VMs.


# Configuration
This client uses the configuration file [xnnbi_config.py](xnnbi_config.py). 
  - `HOSTNAME`: IP or FQDN of the Xtreme Networks endpoint
  - `PORT`: Port to access the API
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)

# Example Config
```
HOSTNAME = ""
PORT = 8443
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires a API Client ID and Secret Key

# Enablement
To utilize this client within the VAR Framework, add `"xtreme_networks_nbi"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation


# Resources
- https://documentation.extremenetworks.com/XMC_API/NBI/8.4_EA/
