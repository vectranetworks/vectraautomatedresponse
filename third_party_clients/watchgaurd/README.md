# Watchguard Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Watchguard Endpoint Security API.  

# Requirements
- __Python packages__
  - requests


# Configuration
This client uses the configuration file [watchguard_config.py](watchguard_config.py). 
  - `URL`: URL for region specific Watchguard endpoint
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)
  
# Example Config
```
URL = ""
CHECK_SSL = False  
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Watchguard credentials with read and write permissions
  - Access ID
  - Password
  - Account ID

# Enablement
To utilize this client within the VAR Framework, add `"watchguard"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__

# Resources
- https://www.watchguard.com/help/docs/API/Content/en-US/endpoint_security/WES_endpoint_security/v1/WES_endpoint_security.html
- __Regional URLs:__ https://www.watchguard.com/help/docs/API/Content/en-US/api_get_started/make_requests.html
