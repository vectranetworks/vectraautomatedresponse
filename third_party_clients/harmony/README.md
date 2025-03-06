# Under Construction

# Harmony Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Elastic Secure Endpoint API.  

# Requirements
- __Python packages__
  - requests

# Configuration
This client uses the configuration file [harmony_config.py](harmony_config.py).
  - `AUTH_URL`: Auth URL provided by _Infinity Portal_
  - `BASE_URL`: Harmony API URL
  - `CHECK_SSL`: set to True to validate server SSL certificates (default: False)
  
# Example Config
```
AUTH_URL = ""
BASE_URL = ""
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - an API Key and Authentication URL created in the _Infinity Portal_ with `Endpoint` in the _Service_ field
# Enablement
To utilize this client within the VAR Framework, add `"harmony"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
 - __Not built__

# Resources
- https://sc1.checkpoint.com/documents/latest/api_reference/index.html#
- https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.221#info