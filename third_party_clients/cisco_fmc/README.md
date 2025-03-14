# Cisco FMC Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cisco FMC API.  

# Requirements
- __Python packages__
  - requests
  - urllib3


# Configuration
This client uses the configuration file [fmc_config.py](fmc_config.py). 
  - `URL`: URL of the Cisco FMC API
  - `BLOCK_GROUP`: Name of group configured in Cisco FMC that has the policies applied for isolation

# Example Config
```
URL=""
BLOCK_GROUP=""
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Cisco FMC username and password with the following permissions:

# Enablement
To utilize this client within the VAR Framework, add `"cisco_fmc"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v6.1 - v6.5

# Resources
- https://www.cisco.com/c/en/us/td/docs/security/firepower/650/api/REST/Firepower_Management_Center_REST_API_Quick_Start_Guide_650.html
