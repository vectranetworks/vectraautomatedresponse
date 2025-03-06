
# CheckPoint Firewall Client

# Overview
This integration provides a way to block source and destination IP addresses identified by Cognito Detect in a Check Point Firewall system. Address group will be created in the Check Point Manager, which can be used to easily configure firewall policies as desired by the user. Source IP addresses and destination IP addresses are assigned to separate address groups.

# Requirements
- __Python packages__
  - requests

- __Checkpoint Address Groups__
  - INTERNAL_ADDRESS_GROUP
  - EXTERNAL_ADDRESS_GROUP

# Configuration
This client uses the configuration file [checkpoint_config.py](checkpoint_config.py). 
  - `USER`: User for the CheckPoint Firewall
  - `HOST`: IPs of the CheckPoint Firewall
  - `PORT`: API port of the CheckPoint Firewall (default: 443)
  - `INTERNAL_ADDRESS_GROUP`: Address group to which to add internal IPs for blocking (E-W traffic). __NOTE__: Used for host-based blocking only.
  - `EXTERNAL_ADDRESS_GROUP`: Address group to which to add external IPs for blocking (N-S traffic). __NOTE__: Used for detection-based blocking only.
  
# Example Config
```
USER = "admin"
HOST = "1.1.1.1"
PORT = 443
INTERNAL_ADDRESS_GROUP = "Internal-Block"
EXTERNAL_ADDRESS_GROUP = "External-Block"
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"checkpoint"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__


# Resources
- https://sc1.checkpoint.com/documents/latest/APIs/#introduction~v2%20