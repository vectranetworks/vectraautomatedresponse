# Deepinstinct EDR Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the DeepInstinct REST API.

# Requirements
- __Python packages__
  - requests

# Configuration
This client uses the configuration file [deepinstinct_edr_config.py](deepinstinct_edr_config.py). 
  - `BASE_URL`: FQDN/URI for the DeepInstinct instance
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)
  
# Example Config
```
BASE_URL = "MYTENNANT.customers.deepinstinctweb.com"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - API Key

# Enablement
To utilize this client within the VAR Framework, add `"deepinstinct_edr"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v1

# Resources
- https://gulfstream.customers.deepinstinctweb.com/api/v1/
