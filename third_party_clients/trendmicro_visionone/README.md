# Trendmicro VisionOne Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Trendmicro VisionOne API.  

# Requirements
- __Python packages__
  - requests


# Configuration
This client uses the configuration file [vision_one_config.py](vision_one_config.py). 
  - `BASE_URL`: URL for the region of Trendmicro VisionOne service
  - `CHECK_SSL`: whether or not to validate server certificate (default: False)

# Example Config
```
BASE_URL = "https://api.xdr.trendmicro.com"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Trendmicro VisionOne API Key

# Enablement
To utilize this client within the VAR Framework, add `"trendmicro_visionone"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation


# Resources
- https://automation.trendmicro.com/xdr/api-v3/
- __Regional Domains:__ https://automation.trendmicro.com/xdr/Guides/Regional-domains/

