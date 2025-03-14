# ClearPass Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the ClearPass API.  
Requires RADIUS Accounting to be enabled on physical switches.

# Requirements
- __Python packages__
  - requests

# Configuration
This client uses the configuration file [clearpass_config.py](clearpass_config.py). 
  - `URL`: URL of the ClearPass Appliance
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
   - ClearPass API Client ID
   - ClearPass API Secret Key (if not a public API Client)
   - Username
   - Password

# Enablement
To utilize this client within the VAR Framework, add `"clearpass"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v6.12.4

# Resources
- https://developer.arubanetworks.com/aruba-cppm/docs/introduction-and-overview
