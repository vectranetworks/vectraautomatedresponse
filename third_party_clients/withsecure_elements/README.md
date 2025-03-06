# WithSecure Elements Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the WithSecure Elements API.  

# Requirements
- __Python packages__
  - requests
  - cachetools

# Configuration
This client uses the configuration file [elements_config.py](elements_config.py). 
  - `BASE_URL`: "https://api.connect.withsecure.com" ; URL FOR THE API
  - `CHECK_SSL`: set to True to verify server SSL certificate (default: False)

# Example Config
```
BASE_URL = "https://api.connect.withsecure.com"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires WithSecure API Client ID and Secret Key with read/write permissions.

# Enablement
To utilize this client within the VAR Framework, add `"withsecure_elements"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- 

# Resources
- https://connect.withsecure.com/getting-started/elements