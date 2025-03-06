# Bitdefender Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Bitdefender API.  

# Requirements
- __Python packages__
  - requests
  - cachetools


# Configuration
This client uses the configuration file [bitdefender_config.py](bitdefender_config.py). 
  - `HOSTNAME`: hostname of the bitdefender server.
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)
  - `BLOCK_MULTIPLE`: whether or not to block multiple hosts per transaction (default: False)

# Example Config
```
HOSTNAME=""
CHECK_SSL=False
BLOCK_MULTIPLE=False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Bitdefender API Key with the following permissions:
  - Companies
  - Incidents
  - Network

# Enablement
To utilize this client within the VAR Framework, add `"bitdefender"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v1.0

# Resources
- https://www.bitdefender.com/business/support/en/77209-125277-public-api.html
