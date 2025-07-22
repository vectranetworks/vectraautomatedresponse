# Pulse Network Access Control Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Pulse NAC API.  

# Requirements
- __Python packages__
  - requests
  - jwt


# Configuration
This client uses the configuration file [pulse_nac_config.py](pulse_nac_config.py). 
  - `PULSE_APPLIANCE`: Pulse NAC appliance IP or hostname
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)
  - `RSA_FILE`: User's private RSA keyfile used in token encoding
  - `RSA_PUB_FILE`: User's public RSA keyfile used in token encoding

# Example Config
```
PULSE_APPLIANCE = ""
CHECK_SSL = False
RSA_FILE = ""
RSA_PUB_FILE = ""
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Pulse NAC Username and Password
  - The client will store the returned authorization API key on the host in a file encoding by the provided RSA_File
- __Note:__ This client is not configured to use Realm-based Authentication

# Enablement
To utilize this client within the VAR Framework, add `"pulse_nac"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__


# Resources
- https://help.ivanti.com/ps/legacy/PCS/9.1Rx/9.1R7/9.1R7-PCS_PPS-REST-API-Solutions-Guide.pdf
- [Pulse NAC API Guide](9.1R7-PCS_PPS-REST-API-Solutions-Guide.pdf)
