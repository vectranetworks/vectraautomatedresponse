# Endgame Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Elastic Secure Endpoint API.  

# Requirements
- __Python packages__
  - requests
  - urllib3

# Configuration
This client uses the configuration file [endgame_config.py](endgame_config.py). 
  - `URL`: URL of the Elastic Secure Endpoint API Appliance
  - `CHECK_SSL`: set to True to validate server SSL certificates (default: False)
  
# Example Config
```
URL = ""
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Elastic Secure Endpoint API Key

# Enablement
To utilize this client within the VAR Framework, add `"endgame"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v8

# Resources
- https://www.elastic.co/docs/api/doc/kibana/v8/group/endpoint-security-endpoint-management-api