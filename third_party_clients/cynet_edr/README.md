# Cynet EDR Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cynet Cloud API.
The Cynet OnPrem deployment does not support the Isolation API endpoint

# Requirements
- __Python packages__
  - requests
  - urllib3

# Configuration
This client uses the configuration file [cynet_edr_config.py](cynet_edr_config.py). 
  - `BASE_URL`: URL used to access CYNET Cloud infrastructure
  - `CHECK_SSL`: Whether or not to validate server TLS certificates (default: False)
  
# Example Config
```
REGION = "your_domain.api.cynet.com"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Username, Password and client_id
        - To obtain your client ID:
            - If you are a single tenant: Contact Cynet to receive your client ID.
            - If you are an MSSP: In the Cynet 360 console, navigate to Global Settings > Client Site Manager > Sites Status. Your sites are listed in this page with their client IDs. 

# Enablement
To utilize this client within the VAR Framework, add `"cynet_edr"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- May 7th, 2025

# Resources
- https://help.api.cynet.com/docs/cynet/iah0dsbmetd0e-welcome-to-cynet-api-reference
