# Tanium Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Tanium API.  

# Requirements
- __Python packages__
  - python-graphql-client


# Configuration
This client uses the configuration file [tanium_config.py](tanium_config.py). 
  - `URL`: URL to access Tanium GraphQL interface
  - `BLOCK_PKG`: List of packages to be applied to hosts for isolation
    - __Note:__ packages must have Mac, Windows, or Linux in the name to allow for package to OS correlation
  - `UNBLOCK_PKG`: List of packages to be applied to hosts for unisolation
    - __Note:__ packages must have Mac, Windows, or Linux in the name to allow for package to OS correlation

# Example Config
```
URL = "https://mytanium-api.cloud.tanium.com"
BLOCK_PKG = ["Apply Mac PF Quarantine", "Apply Windows IPsec Quarantine"]
UNBLOCK_PKG = ["Remove Mac PF Quarantine", "Remove Windows IPsec Quarantine]

```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Tanium API Key with Incident Response permissions:

# Enablement
To utilize this client within the VAR Framework, add `"tanium"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- 

# Resources
- https://developer.tanium.com/site/global/docs/api_reference/index.gsp
