# Trendmicro CloudOne Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Trendmicro CloudOne API.  

# Requirements
- __Python packages__
  - requests

# Configuration
This client uses the configuration file [cloudone.py](cloudone_config.py). 
  - `BASE_URL`: URL of the Trendmicro CloudOne workload that includes a region.
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)

# Example Config
```
BASE_URL = "https://workload.us-1.cloudone.trendmicro.com"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Trendmicro CloudOne API Key

# Enablement
To utilize this client within the VAR Framework, add `"trendmicro_cloudone"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation


# Resources
- https://cloudone.trendmicro.com/docs/workload-security/api-reference/
- __Regional Domains:__ https://cloudone.trendmicro.com/docs/identity-and-account-management/c1-regions/