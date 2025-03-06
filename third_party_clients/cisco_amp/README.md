# Cisco AMP Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cisco AMP API.  

# Requirements
- __Python packages__
  - requests
  - urllib3


# Configuration
This client uses the configuration file [amp_config.py](amp_config.py). 
  - `URL`: URL of the Cisco AMP API
    - __NOTE:__ Uncomment the desired Cisco AMP API URL based on region.

# Example Config
```
URL = "https://api.amp.cisco.com" # North America
# URL = "https://api.apjc.amp.cisco.com" # Asia Pacific, Japan, China
# URL = "https://api.consumer.amp.cisco.com" # Consumer
# URL = "https://api.eu.amp.cisco.com" # Europe
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Cisco AMP Client ID and API Key with the following permissions:
  - Companies
  - Incidents
  - Network

# Enablement
To utilize this client within the VAR Framework, add `"cisco_amp"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v1

# Resources
- https://developer.cisco.com/docs/secure-endpoint/introduction/#secure-endpoint-api
