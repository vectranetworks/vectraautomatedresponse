# Forti EDR Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Elastic Secure Endpoint API.  

# Requirements
- __Python packages__
  - fortiedr
  - urllib3

# Configuration
This client uses the configuration file [forti_edr_config.py](forti_edr_config.py). 
  - `HOSTNAME`: Hostname for the FortiEDR server
  - `ORGANIZATION`: Organization name IF needed. Case sensitive
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)
  
# Example Config
```
HOSTNAME = ""
ORGANIZATION = ""
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"forti_edr"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v8

# Resources
- https://pypi.org/project/fortiedr/
- https://docs.fortinet.com/document/fortiedr/7.0.0/administration-guide/807495/administration