# Sophos EDR Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Sophos Endpoint API.  
Integration requires 'Intercept X Advanced with XDR' license on Sophos side

# Requirements
- __Python packages__
  - urllib3

# Configuration
This client uses the configuration file [sophos_edr_config.py](sophos_edr_config.py). 
  - `AUTH_URL`: Endpoint to authenticate and fetch tokens
  - `WHOAMI_URL`: Endpoint to retrieve the partner, organization or tenant UUID from the security context
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)
  
# Example Config
```
AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
CHECK_SSL = False
** These are the same for all environments and do not need to be changed **
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - client_id and client_secret

# Enablement
To utilize this client within the VAR Framework, add `"sophos_edr"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
Tested in production environment by Telonic GmbH.

# Resources
- https://developer.sophos.com/docs/endpoint-v1/1/overview
