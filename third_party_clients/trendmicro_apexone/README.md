# Bitdefender Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Bitdefender API.  

# Requirements
- __Python packages__
  - requests
  - jwt


# Configuration
This client uses the configuration file [apex_one_config.py](apex_one_config.py). 
  - `BASE_URL`: The URL of the Apex Central server without the WebApp
  - `API_PATH`: API path appended to BASE_URL "/WebApp/API/AgentResource/ProductAgents"

# Example Config
```
BASE_URL = "https://<update>.manage.trendmicro.com"
API_PATH = "/WebApp/API/AgentResource/ProductAgents"
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires TrendMicro Apex One Application ID and API Key

# Enablement
To utilize this client within the VAR Framework, add `"trendmicro_apexone"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation


# Resources
- https://automation.trendmicro.com/apex-central/Guides/Getting-Started/
