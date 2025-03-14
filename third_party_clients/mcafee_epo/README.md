# McAfee EPO Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the McAfee EPO API.  

# Requirements
- __Python packages__
  - requests


# Configuration
This client uses the configuration file [mcafee_config.py](mcafee_config.py). 
  - `HOSTNAME`: hostname of the McAfee EPO server.
  - `PORT`: Port to connect to the McAfee EPO Server (default: 8443)
  - `TAGID`: the Tag ID to be applied to or removed from a host for isolation/unisolation

# Example Config
```
HOSTNAME = ""
PORT = ""
TAGID = ""
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires McAfee Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"mcafee"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__

# Resources
- https://docs.trellix.com/bundle/epolicy-orchestrator-web-api-reference-guide/page/GUID-2503B69D-2BCE-4491-9969-041838B39C1F.html
