# ESET EDR Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the ESET API.  

# Requirements
- __Python packages__
  - requests
  - urllib3

# Configuration
This client uses the configuration file [eset_edr_config.py](eset_edr_config.py). 
  - `REGION`: Region where the deployment is located(eu, de, us, jpn,ca)
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)
  
# Example Config
```
REGION = "eu"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"eset_edr"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- May 7th, 2025

# Resources
- https://help.eset.com/eset_connect/en-US/index.html
